import os
import time
import asyncio
import logging
import sqlite3
from collections import defaultdict, deque
from datetime import timedelta

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "0") or 0)
QUARANTINE_ROLE_ID = int(os.getenv("QUARANTINE_ROLE_ID", "0") or 0)
RAID_JOIN_LIMIT = int(os.getenv("RAID_JOIN_LIMIT", "8"))
RAID_WINDOW_SECONDS = int(os.getenv("RAID_WINDOW_SECONDS", "20"))
NUKE_ACTION_LIMIT = int(os.getenv("NUKE_ACTION_LIMIT", "3"))
NUKE_WINDOW_SECONDS = int(os.getenv("NUKE_WINDOW_SECONDS", "12"))
SPAM_MESSAGE_LIMIT = int(os.getenv("SPAM_MESSAGE_LIMIT", "6"))
SPAM_WINDOW_SECONDS = int(os.getenv("SPAM_WINDOW_SECONDS", "7"))
MIN_ACCOUNT_AGE_DAYS = int(os.getenv("MIN_ACCOUNT_AGE_DAYS", "3"))
DB_PATH = os.getenv("DB_PATH", "data/security.sqlite3")

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN is missing. Copy .env.example to .env and set it.")

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("simba-security")

intents = discord.Intents.default()
intents.guilds = True
intents.members = True             # Enable Server Members Intent in Developer Portal
intents.moderation = True
intents.message_content = True     # Enable Message Content Intent in Developer Portal

bot = commands.Bot(command_prefix="!", intents=intents)
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.execute("PRAGMA journal_mode=WAL")
db.executescript("""
CREATE TABLE IF NOT EXISTS allowlist (
    guild_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    added_by INTEGER NOT NULL,
    PRIMARY KEY (guild_id, user_id)
);
CREATE TABLE IF NOT EXISTS settings (
    guild_id INTEGER PRIMARY KEY,
    lockdown INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS overwrite_snapshot (
    guild_id INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    allow_value INTEGER NOT NULL,
    deny_value INTEGER NOT NULL,
    PRIMARY KEY (guild_id, channel_id)
);
""")
db.commit()

join_events = defaultdict(deque)
audit_events = defaultdict(deque)
message_events = defaultdict(deque)
raid_until = defaultdict(float)
spam_strikes = defaultdict(int)

def is_allowlisted(guild_id: int, user_id: int) -> bool:
    row = db.execute(
        "SELECT 1 FROM allowlist WHERE guild_id=? AND user_id=?",
        (guild_id, user_id),
    ).fetchone()
    return row is not None

async def send_log(guild: discord.Guild, title: str, description: str, color=discord.Color.orange()):
    if not LOG_CHANNEL_ID:
        return
    channel = guild.get_channel(LOG_CHANNEL_ID)
    if not isinstance(channel, discord.TextChannel):
        return
    embed = discord.Embed(title=title, description=description[:4000], color=color, timestamp=discord.utils.utcnow())
    try:
        await channel.send(embed=embed)
    except discord.Forbidden:
        log.warning("Cannot send security log in guild %s", guild.id)

async def quarantine(member: discord.Member, reason: str):
    if not QUARANTINE_ROLE_ID:
        return False
    role = member.guild.get_role(QUARANTINE_ROLE_ID)
    if role is None or role >= member.guild.me.top_role:
        await send_log(member.guild, "Quarantaine impossible", "Le rôle configuré est absent ou placé au-dessus du rôle du bot.", discord.Color.red())
        return False
    try:
        await member.add_roles(role, reason=reason)
        await send_log(member.guild, "Membre mis en quarantaine", f"{member.mention} (`{member.id}`)\nMotif : {reason}")
        return True
    except (discord.Forbidden, discord.HTTPException) as exc:
        log.warning("Quarantine failed for %s: %s", member.id, exc)
        return False

async def contain_actor(guild: discord.Guild, user_id: int, reason: str):
    if is_allowlisted(guild.id, user_id):
        await send_log(guild, "Action sensible autorisée", f"Utilisateur whitelisté : <@{user_id}> (`{user_id}`)\nAction : {reason}", discord.Color.green())
        return
    member = guild.get_member(user_id)
    if member is None:
        try:
            member = await guild.fetch_member(user_id)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            member = None
    if member is None or member.id == guild.owner_id or member == guild.me:
        await send_log(guild, "Alerte Anti-Nuke", f"Action suspecte : {reason}\nAuteur : `{user_id}`\nLe bot n'a pas pu appliquer de confinement automatique.", discord.Color.red())
        return
    try:
        removable = [
            role for role in member.roles
            if role != guild.default_role and not role.managed and role < guild.me.top_role
        ]
        if removable:
            await member.remove_roles(*removable, reason=f"SIMBA SECURITY: {reason}")
        await send_log(
            guild, "🚨 Anti-Nuke : auteur confiné",
            f"Utilisateur : {member.mention} (`{member.id}`)\nAction détectée : {reason}\nRôles retirés : {len(removable)}",
            discord.Color.red(),
        )
    except (discord.Forbidden, discord.HTTPException) as exc:
        await send_log(guild, "🚨 Anti-Nuke : intervention échouée", f"Auteur : `{user_id}`\nAction : {reason}\nErreur : `{type(exc).__name__}`", discord.Color.red())

@bot.event
async def on_ready():
    try:
        synced = await bot.tree.sync()
        log.info("Logged in as %s; synced %d commands", bot.user, len(synced))
    except Exception:
        log.exception("Slash command sync failed")
    log.info("SIMBA SECURITY is online.")

@bot.event
async def on_member_join(member: discord.Member):
    now = time.monotonic()
    events = join_events[member.guild.id]
    events.append((now, member.id))
    while events and now - events[0][0] > RAID_WINDOW_SECONDS:
        events.popleft()

    account_age = discord.utils.utcnow() - member.created_at
    if account_age < timedelta(days=MIN_ACCOUNT_AGE_DAYS):
        await send_log(
            member.guild, "Compte récent détecté",
            f"{member.mention} (`{member.id}`) — compte créé il y a environ {account_age.days} jour(s).",
        )

    if now < raid_until[member.guild.id]:
        await quarantine(member, "Mode Anti-Raid actif")
        return

    if len(events) >= RAID_JOIN_LIMIT:
        raid_until[member.guild.id] = now + 5 * 60
        await send_log(
            member.guild, "🚨 ALERTE ANTI-RAID",
            f"{len(events)} arrivées en {RAID_WINDOW_SECONDS} secondes. Quarantaine automatique pendant 5 minutes.",
            discord.Color.red(),
        )
        for _, member_id in list(events):
            existing = member.guild.get_member(member_id)
            if existing:
                await quarantine(existing, "Arrivées massives détectées (Anti-Raid)")
        return

    if account_age < timedelta(days=MIN_ACCOUNT_AGE_DAYS):
        await quarantine(member, "Compte trop récent")

@bot.event
async def on_audit_log_entry_create(entry: discord.AuditLogEntry):
    guild = entry.guild
    actor_id = entry.user_id
    if not guild or not actor_id or actor_id == (bot.user.id if bot.user else 0):
        return

    sensitive = {
        discord.AuditLogAction.channel_delete: "suppression de salon",
        discord.AuditLogAction.role_delete: "suppression de rôle",
        discord.AuditLogAction.webhook_create: "création de webhook",
        discord.AuditLogAction.bot_add: "ajout de bot",
        discord.AuditLogAction.ban: "bannissement",
        discord.AuditLogAction.kick: "expulsion",
    }
    label = sensitive.get(entry.action)
    if not label:
        return

    key = (guild.id, actor_id, str(entry.action))
    now = time.monotonic()
    events = audit_events[key]
    events.append(now)
    while events and now - events[0] > NUKE_WINDOW_SECONDS:
        events.popleft()

    if len(events) >= NUKE_ACTION_LIMIT:
        events.clear()
        await contain_actor(guild, actor_id, f"{label} répété(e) {NUKE_ACTION_LIMIT} fois en {NUKE_WINDOW_SECONDS}s")

@bot.event
async def on_message(message: discord.Message):
    if message.guild and not message.author.bot and isinstance(message.author, discord.Member):
        now = time.monotonic()
        key = (message.guild.id, message.author.id)
        events = message_events[key]
        events.append(now)
        while events and now - events[0] > SPAM_WINDOW_SECONDS:
            events.popleft()

        too_many_mentions = len(message.mentions) >= 5 or len(message.role_mentions) >= 3
        too_fast = len(events) >= SPAM_MESSAGE_LIMIT
        if (too_fast or too_many_mentions) and not is_allowlisted(message.guild.id, message.author.id):
            try:
                await message.delete()
            except (discord.Forbidden, discord.NotFound, discord.HTTPException):
                pass
            spam_strikes[key] += 1
            try:
                duration = min(60, 10 * spam_strikes[key])
                await message.author.timeout(timedelta(seconds=duration), reason="SIMBA SECURITY: spam/flood")
            except (discord.Forbidden, discord.HTTPException):
                pass
            await send_log(
                message.guild, "Anti-Spam déclenché",
                f"{message.author.mention} (`{message.author.id}`) — flood ou mentions excessives. Sanction tentée : {duration if 'duration' in locals() else 0}s.",
            )
    await bot.process_commands(message)

def admin_check(interaction: discord.Interaction) -> bool:
    return bool(interaction.guild and interaction.user.guild_permissions.manage_guild)

security = app_commands.Group(name="security", description="Commandes SIMBA SECURITY")

@security.command(name="status", description="Afficher l'état des protections")
async def status(interaction: discord.Interaction):
    if not admin_check(interaction):
        await interaction.response.send_message("Permission Gérer le serveur requise.", ephemeral=True)
        return
    lockdown = db.execute("SELECT lockdown FROM settings WHERE guild_id=?", (interaction.guild_id,)).fetchone()
    allowed = db.execute("SELECT COUNT(*) FROM allowlist WHERE guild_id=?", (interaction.guild_id,)).fetchone()[0]
    embed = discord.Embed(title="SIMBA SECURITY — Statut", color=discord.Color.green())
    embed.add_field(name="Anti-Raid", value="Actif", inline=True)
    embed.add_field(name="Anti-Nuke", value="Actif", inline=True)
    embed.add_field(name="Anti-Spam", value="Actif", inline=True)
    embed.add_field(name="Lockdown", value="Activé" if lockdown and lockdown[0] else "Désactivé", inline=True)
    embed.add_field(name="Whitelist", value=str(allowed), inline=True)
    embed.set_footer(text="La protection dépend aussi des permissions et intents Discord.")
    await interaction.response.send_message(embed=embed, ephemeral=True)

@security.command(name="allow-add", description="Ajouter un utilisateur à la whitelist")
@app_commands.describe(user="Utilisateur de confiance")
async def allow_add(interaction: discord.Interaction, user: discord.Member):
    if not admin_check(interaction) or interaction.user.id != interaction.guild.owner_id:
        await interaction.response.send_message("Seul le propriétaire du serveur peut modifier la whitelist.", ephemeral=True)
        return
    db.execute("INSERT OR IGNORE INTO allowlist VALUES (?, ?, ?)", (interaction.guild_id, user.id, interaction.user.id))
    db.commit()
    await interaction.response.send_message(f"{user.mention} ajouté à la whitelist.", ephemeral=True)

@security.command(name="allow-remove", description="Retirer un utilisateur de la whitelist")
@app_commands.describe(user="Utilisateur à retirer")
async def allow_remove(interaction: discord.Interaction, user: discord.Member):
    if not admin_check(interaction) or interaction.user.id != interaction.guild.owner_id:
        await interaction.response.send_message("Seul le propriétaire du serveur peut modifier la whitelist.", ephemeral=True)
        return
    db.execute("DELETE FROM allowlist WHERE guild_id=? AND user_id=?", (interaction.guild_id, user.id))
    db.commit()
    await interaction.response.send_message(f"{user.mention} retiré de la whitelist.", ephemeral=True)

@security.command(name="lockdown", description="Bloquer temporairement l'envoi de messages par @everyone")
async def lockdown(interaction: discord.Interaction):
    if not admin_check(interaction) or interaction.user.id != interaction.guild.owner_id:
        await interaction.response.send_message("Seul le propriétaire peut déclencher le lockdown.", ephemeral=True)
        return
    guild = interaction.guild
    db.execute("DELETE FROM overwrite_snapshot WHERE guild_id=?", (guild.id,))
    changed = 0
    for channel in guild.text_channels:
        overwrite = channel.overwrites_for(guild.default_role)
        allow, deny = overwrite.pair()
        db.execute(
            "INSERT OR REPLACE INTO overwrite_snapshot VALUES (?, ?, ?, ?)",
            (guild.id, channel.id, allow.value, deny.value),
        )
        try:
            await channel.set_permissions(guild.default_role, send_messages=False, reason="SIMBA SECURITY lockdown")
            changed += 1
        except (discord.Forbidden, discord.HTTPException):
            continue
    db.execute("INSERT OR REPLACE INTO settings VALUES (?, 1)", (guild.id,))
    db.commit()
    await interaction.response.send_message(f"Lockdown activé sur {changed} salons texte. Utilise `/security unlock` pour restaurer les permissions enregistrées.", ephemeral=True)
    await send_log(guild, "Lockdown activé", f"Déclenché par {interaction.user.mention}. Salons modifiés : {changed}.", discord.Color.red())

@security.command(name="unlock", description="Restaurer les permissions @everyone enregistrées avant le lockdown")
async def unlock(interaction: discord.Interaction):
    if not admin_check(interaction) or interaction.user.id != interaction.guild.owner_id:
        await interaction.response.send_message("Seul le propriétaire peut désactiver le lockdown.", ephemeral=True)
        return
    guild = interaction.guild
    rows = db.execute("SELECT channel_id, allow_value, deny_value FROM overwrite_snapshot WHERE guild_id=?", (guild.id,)).fetchall()
    restored = 0
    for channel_id, allow_value, deny_value in rows:
        channel = guild.get_channel(channel_id)
        if not isinstance(channel, discord.TextChannel):
            continue
        overwrite = discord.PermissionOverwrite.from_pair(discord.Permissions(allow_value), discord.Permissions(deny_value))
        try:
            await channel.set_permissions(guild.default_role, overwrite=overwrite, reason="SIMBA SECURITY unlock")
            restored += 1
        except (discord.Forbidden, discord.HTTPException):
            continue
    db.execute("DELETE FROM overwrite_snapshot WHERE guild_id=?", (guild.id,))
    db.execute("INSERT OR REPLACE INTO settings VALUES (?, 0)", (guild.id,))
    db.commit()
    await interaction.response.send_message(f"Lockdown désactivé. Permissions restaurées sur {restored} salons.", ephemeral=True)
    await send_log(guild, "Lockdown désactivé", f"Permissions restaurées par {interaction.user.mention}.", discord.Color.green())

bot.tree.add_command(security)

async def main():
    async with bot:
        await bot.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
