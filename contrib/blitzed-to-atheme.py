import MySQLdb
import encodings.rot_13
import time

# Blitzed nickserv flags
NS_FORBID = 0x0002
NS_NO_EXPIRE = 0x0004
NS_IDENTIFIED = 0x8000
NS_RECOGNIZED = 0x4000
NS_ON_ACCESS = 0x2000
NS_KILL_HELD = 0x1000
NS_GUESTED = 0x0100
NS_REGAINED = 0x0200
NS_TEMPORARY = 0xFF00
NI_ENFORCE = 0x00000001
NI_SECURE = 0x00000002
NI_MEMO_HARDMAX = 0x00000008
NI_MEMO_SIGNON = 0x00000010
NI_MEMO_RECEIVE = 0x00000020
NI_PRIVATE = 0x00000040
NI_HIDE_EMAIL = 0x00000080
NI_HIDE_MASK = 0x00000100
NI_HIDE_QUIT = 0x00000200
NI_ENFORCEQUICK = 0x00000400
NI_NOOP = 0x00000800
NI_IRCOP = 0x00001000
NI_MARKED = 0x00002000
NI_NOSENDPASS = 0x00004000
NI_AUTOJOIN = 0x00008000
NI_AUTOPROMOTE = 0x00010000
NI_SUSPENDED = 0x10000000

# Blitzed channel flags
CI_KEEPTOPIC=    0x00000001
CI_SECUREOPS=    0x00000002
CI_PRIVATE=  0x00000004
CI_TOPICLOCK=    0x00000008
CI_RESTRICTED=   0x00000010
CI_LEAVEOPS= 0x00000020
CI_SECURE=    0x00000040
CI_FORBID=    0x00000080
CI_NO_EXPIRE= 0x00000200
CI_MEMO_HARDMAX=  0x00000400
CI_VERBOSE=   0x00000800


# Atheme nickserv flags
#struct gflags mu_flags[] = {
#    { 'h', MU_HOLD },
#    { 'n', MU_NEVEROP },
#    { 'o', MU_NOOP },
#    { 'W', MU_WAITAUTH },
#    { 's', MU_HIDEMAIL },
#    { 'm', MU_NOMEMO },
#    { 'e', MU_EMAILMEMOS },
#    { 'C', MU_CRYPTPASS },
#    { 'b', MU_NOBURSTLOGIN },
#    { 'E', MU_ENFORCE },
#    { 'P', MU_USE_PRIVMSG },
#    { 'p', MU_PRIVATE },
#    { 'Q', MU_QUIETCHG },
#    { 'g', MU_NOGREET },
#    { 'r', MU_REGNOLIMIT },
#    { 0, 0 },
#};

#Atheme channel flags
#struct gflags mc_flags[] = {
#    { 'h', MC_HOLD },
#    { 'o', MC_NOOP },
#    { 'l', MC_LIMITFLAGS },
#    { 'z', MC_SECURE },
#    { 'v', MC_VERBOSE },
#    { 'r', MC_RESTRICTED },
#    { 'k', MC_KEEPTOPIC },
#    { 't', MC_TOPICLOCK },
#    { 'g', MC_GUARD },
#    { 'p', MC_PRIVATE },
#    { 0, 0 },
#};

#Atheme channel access flags
#struct flags_table chanacs_flags[255] = {
#    ['v'] = {CA_VOICE, 0, true,      "voice"},
#    ['V'] = {CA_AUTOVOICE, 0, true,  "autovoice"},
#    ['o'] = {CA_OP, 0, true,         "op"},
#    ['O'] = {CA_AUTOOP, 0, true,     "autoop"},
#    ['t'] = {CA_TOPIC, 0, true,      "topic"},
#    ['s'] = {CA_SET, 0, true,        "set"},
#    ['r'] = {CA_REMOVE, 0, true,     "remove"},
#    ['i'] = {CA_INVITE, 0, true,     "invite"},
#    ['R'] = {CA_RECOVER, 0, true,    "recover"},
#    ['f'] = {CA_FLAGS, 0, true,      "acl-change"},
#    ['h'] = {CA_HALFOP, 0, true,     "halfop"},
#    ['H'] = {CA_AUTOHALFOP, 0, true, "autohalfop"},
#    ['A'] = {CA_ACLVIEW, 0, true,    "acl-view"},
#    ['F'] = {CA_FOUNDER, 0, false,   "founder"},
#    ['q'] = {CA_USEOWNER, 0, true,   "owner"},
#    ['a'] = {CA_USEPROTECT, 0, true, "protect"},
#    ['b'] = {CA_AKICK, 0, false,     "banned"},
#};

#This is charybdhis sepecific
CMODE_MAP = {
                0x00000001 : 0x00000001, # +i
                0x00000002 : 0x00000008, # +m
                0x00000004 : 0x00000010, # +n
                0x00000008 : 0x00000040, # +p
                0x00000010 : 0x00000080, # +s
                0x00000020 : 0x00000100, # +t
                0x00000040 : 0x00000002, # +k
                0x00000080 : 0x00000004, # +l
                0x00000100 : 0x00002000, # +R -> +r
                0x00000400 : 0x00001000, # +c
                0x00000800 : 0x00800000  # +O
            }


CFLAGS_MAP = {
                CI_KEEPTOPIC : "k",
                CI_SECUREOPS : "z",
                CI_TOPICLOCK : "t",
                CI_RESTRICTED : "r",
                CI_NO_EXPIRE : "h",
                CI_VERBOSE : "v",
                CI_PRIVATE : "p"
             }

LEVELS_MAP = {
                0 : (5,      "i"),       #CA_INVITE
                1 : (10,     "r"),       #CA_AKICK (deprecated to ACL-CHANGE)
                2 : (-10000, "s"),       #CA_SET
                #                        #CA_UNBAN (deprecated)
                4 : (5,      "O"),       #CA_AUTOOP
                #                        #CA_AUTODEOP (deprecated)
                6 : (3,      "V"),       #CA_AUTOVOICE
                7 : (5,      "o"),       #CA_OPDEOP
                8 : (1,      "A"),       #CA_ACCESS_LIST
                9 : (-10000, "R"),       #CA_CLEAR
                10: (-2,     "b"),       #CA_NOJOIN
                11: (10,     "f"),       #CA_ACCESS_CHANGE
                #                        #CA_MEMO_READ (deprecated)
                #                        #CA_LEVEL_LIST (deprecated)
                #                        #CA_LEVEL_CHANGE (deprecated)
                #                        #CA_SYNC (deprecated)
                #                        #CA_KICK matches +r (KICK/BAN)

             }

def main():
    servicesdb = open('services.db', 'w')
    rwatchdb = open('rwatch.db', 'w')
    db = MySQLdb.connect("localhost", "services", "services", "services")
    cursor = db.cursor(cursorclass=MySQLdb.cursors.DictCursor)

    write_header(servicesdb)
    write_nicks(cursor, servicesdb)
    write_forbidden_nicks(cursor, servicesdb)
    write_nick_links(cursor, servicesdb)
    write_nick_access(cursor, servicesdb)
    write_memos(cursor, servicesdb)
    write_channels(db, cursor, servicesdb)
    write_footer(servicesdb)
   
    write_quarantine(cursor, rwatchdb)

    servicesdb.close()
    rwatchdb.close()

def find_true_nick(db, nick_id):

    cursor = db.cursor(cursorclass=MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT nick,link_id FROM nick WHERE nick_id=%u" % nick_id)
    row = cursor.fetchone()

    if row == None:
        return ""

    if (row['link_id'] == 0):
        return row['nick']
  
    cursor.execute("SELECT nick,nick_id FROM nick WHERE nick_id=%u" % row['link_id'])
    row = cursor.fetchone()
    
    return row['nick']

def write_header(f):
    f.write("DBV 8\n")
    f.write("CF +AFORVbfiorstv\n")

def write_nicks(cursor, f):
    cursor.execute("SELECT * FROM nick WHERE time_registered > 0 AND link_id = 0")

    for row in cursor.fetchall():
        blitzed_flags = int(row['flags'])

        flags = "+C"

        if (blitzed_flags & NI_HIDE_EMAIL):
            flags += "s" 
        
        if (blitzed_flags & NI_NOOP):
            flags += "o"

        if (blitzed_flags & NI_HIDE_MASK or 
            blitzed_flags & NI_HIDE_QUIT):
            flags += "p"

        if (blitzed_flags & NS_NO_EXPIRE or
            blitzed_flags & NI_IRCOP):
            flags += "h"

        f.write("MU %s $rawsha1$%s$salt$%s %s %s %s %s %s\n" % (
                row['nick'],
                row['pass'],
                row['salt'],
                row['email'],
                row['time_registered'],
                row['last_seen'],
                flags,
                "en"   
            ))

        if (blitzed_flags & NI_ENFORCE):
            f.write("MDU %s private:doenforce 1\n" % (
                row['nick']
            ))

        if (len(row['url']) > 0):
            f.write("MDU %s url %s\n" % (
                    row['nick'],
                    row['url']
            ))

        if (row['lat'] > 0 and row['lng'] > 0):
            f.write("MDU %s coords %s %s\n" % (
                    row['nick'],
                    row['lat'],
                    row['lng'],
            ))

def write_forbidden_nicks(cursor, f):
    cursor.execute("SELECT * FROM nick WHERE time_registered = 0")

    for row in cursor.fetchall():
        flags = "+hb"
        f.write("MU %s * noemail %s %s %s %s\n" % (
                row['nick'],
                row['time_registered'],
                row['last_seen'],
                flags,
                "en"   
            ))
        
        f.write("MDU %s private:doenforce 1\n" % (
            row['nick']
        ))
            
        f.write("MDU %s private:freeze:freezer services\n" % (
            row['nick']
        ))

        f.write("MDU %s private:freeze:reason %s\n" % ( 
            row['nick'],
            row['forbid_reason']
        ))

        f.write("MDU %s private:freeze:timestamp %u\n" % (
            row['nick'],
            int(time.time())
        ))

def write_nick_links(cursor, f):
    cursor.execute("SELECT nick.nick as nick,linked_nicks.nick as linked_nick, " +
                   "linked_nicks.time_registered as time_registered, " +
                   "linked_nicks.last_seen as last_seen " + 
                   "FROM nick,nick as linked_nicks " +
                   "WHERE linked_nicks.link_id=nick.nick_id " +
                   "AND linked_nicks.time_registered > 0 " +
                   "AND linked_nicks.link_id > 0")

    for row in cursor.fetchall():
        f.write("MN %s %s %s %s\n" % (
                row['nick'],
                row['linked_nick'],
                row['time_registered'],
                row['last_seen']
            ))

def write_nick_access(cursor, f):
    cursor.execute("SELECT nick,userhost FROM nick,nickaccess " +
                    "WHERE nickaccess.nick_id=nick.nick_id")

    for row in cursor.fetchall():
        f.write("AC %s %s\n" % (
                row['nick'],
                row['userhost']
            ))

def write_memos(cursor, f):
    cursor.execute("SELECT * FROM memo")
    decoder = encodings.rot_13.Codec()

    for row in cursor.fetchall():
        text = decoder.decode(row['text'])
        f.write("ME %s %s %s 1 %s\n" % (
                row['owner'],
                row['sender'],
                row['time'],
                text[0].encode('utf-8')
            ))

def cmode_convert(inflags):
    outflags = 0
    for flag in CMODE_MAP.keys():
        if inflags & flag:
            outflags |= CMODE_MAP[flag]
    return outflags 

def cflag_convert(inflags):
    outflags = "+"
    for flag in CFLAGS_MAP.keys():
        if inflags & flag:
            outflags += CFLAGS_MAP[flag]
    return outflags

def write_channels(db, cursor, f):
    
    cursor.execute("SELECT * FROM channel WHERE time_registered > 0 AND founder > 0")

    cflags_map = {
                    CI_KEEPTOPIC : "k",
                    CI_SECUREOPS : "z",
                    CI_TOPICLOCK : "t",
                 }

    for chan in cursor.fetchall():

        flags = cflag_convert(chan['flags']) 
        mlock_on = cmode_convert(int(chan['mlock_on']))
        mlock_off = cmode_convert(int(chan['mlock_off']))

        f.write("MC %s %s %s %s %s %s %s %s\n" % (
                chan['name'],
                chan['time_registered'],
                chan['last_used'],
                flags,
                mlock_on,
                mlock_off,
                chan['mlock_limit'],
                chan['mlock_key']
            ))

        if len(chan['url']) > 0:
            f.write("MDC %s url %s\n" % (
                    chan['name'],
                    chan['url']
                ))

        if len(chan['description']) > 0:
            f.write("MDC %s description %s\n" % (
                    chan['name'],
                    chan['description']
                ))

        if len(chan['entry_message']) > 0:
            f.write("MDC %s private:entrymsg %s\n" % (
                    chan['name'],
                    chan['entry_message']
                ))
        if len(chan['last_topic']) > 0:
            f.write("MDC %s private:topic:text %s\n" % (
                    chan['name'],
                    chan['last_topic']
                ))
            f.write("MDC %s private:topic:setter %s\n" % (
                    chan['name'],
                    chan['last_topic_setter']
                ))
            f.write("MDC %s private:topic:ts %lu\n" % (
                    chan['name'],
                    chan['last_topic_time']
                ))

        write_channel_access(db, chan, f)
        write_channel_bans(db, chan, f)

def write_channel_access(db, chan, f):

    cursor = db.cursor(cursorclass=MySQLdb.cursors.DictCursor)
 
    #make a copy of default levels
    levels = LEVELS_MAP.copy() 

    cursor.execute("SELECT * FROM chanlevel " +
                   "WHERE channel_id=%s" % chan['channel_id'])

    #update default level with any changes from DB
    for row in cursor.fetchall():
        if row['what'] in levels:
            entry = levels[row['what']]
            levels[row['what']] = (row['level'], entry[1])

    # nick -> set of flags
    access_list = dict()
    cursor.execute("SELECT * FROM chanaccess WHERE channel_id=%s" % chan['channel_id'])

    #add founder and successor now
    founder_nick = find_true_nick(db, chan['founder'])
    access_list[founder_nick] = set(["F","A","O","R","f","i","o","r","s","t","v"])

    if len(founder_nick) == 0:
        return

    if chan['successor'] != 0:
        successor_nick = find_true_nick(db, chan['successor'])
        if successor_nick not in access_list:
             access_list[successor_nick] = set(["S"])

    #combine flags of nicks under same account
    #into a set before writing out the master nick
    for row in cursor.fetchall():
        nick = find_true_nick(db, row['nick_id'])
        if not nick in access_list:
            access_list[nick] = set()

        for level in levels.values():
            if (int(row['level']) >= level[0]) and (level[0]  >= 0):
                access_list[nick].add(level[1])
            if (int(row['level']) <= level[0]) and (level[0]   < 0):
                access_list[nick].add(level[1])

    for nick in access_list.keys():
        flags = "+" + "".join(access_list[nick])
        f.write("CA %s %s %s %u\n" % (
                chan['name'],
                nick,
                flags,
                int(time.time()) 
           ))

def write_channel_bans(db, chan, f):

    cursor = db.cursor(cursorclass=MySQLdb.cursors.DictCursor)

    cursor.execute("SELECT * FROM akick " +
                   "WHERE channel_id=%s" % chan['channel_id'])


    for row in cursor.fetchall():
        #akick on a nick
        if row['nick_id'] > 0:
            target = find_true_nick(db, row['nick_id'])
        else:
            target = row['mask']
        
        f.write("CA %s %s +b %u\n" % (
                chan['name'],
                target,
                row['added']
            ))
        f.write("MDA %s:%s reason %s\n" % (
                chan['name'],
                target,
                row['reason']
            ))

def write_quarantine(cursor, f):
   
    cursor.execute("SELECT * FROM quarantine")

    for row in cursor.fetchall():
        f.write("RW 0 %s\n" % (
                row['regex']
            ))
        f.write("RR 2 %s\n" % (
                row['reason']
            ))

def write_footer(f):
    f.write("GDBV 3\n")
    f.write("KID 0\n")
    f.write("XID 0\n")
    f.write("QID 0\n")
    f.write("DE 1 0 0 0 0 0\n")

if __name__ == "__main__":
    main()
