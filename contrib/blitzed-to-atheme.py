import MySQLdb

NS_FORBID = 0x0002
NS_NO_EXPIRE = 0x0004
NS_IDENTIFIED = 0x8000
NS_RECOGNIZED = 0x4000
#user comes from known address
NS_ON_ACCESS = 0x2000
#being held after enforcement
NS_KILL_HELD = 0x1000
NS_GUESTED = 0x0100
NS_REGAINED = 0x0200
NS_TEMPORARY = 0xFF00

#/*! \brief SVSNICK others who take this nick. */
NI_ENFORCE = 0x00000001
# /*! \brief Don't recognise unless IDENTIFY'd. */
NI_SECURE = 0x00000002
# /*! \brief Don't allow user to change memo limit. */
NI_MEMO_HARDMAX = 0x00000008
# /*! \brief Notify of memos at signon and un-away. */
NI_MEMO_SIGNON = 0x00000010
# /*! \brief Notify of new memos when sent. */
NI_MEMO_RECEIVE = 0x00000020
# /*! \brief Don't show in NickServ LIST to non-services-admins. */
NI_PRIVATE = 0x00000040
# /*! \brief Don't show E-mail address in NickServ INFO. */
NI_HIDE_EMAIL = 0x00000080
# /*! \brief Don't show last seen address in NickServ INFO. */
NI_HIDE_MASK = 0x00000100
# /*! \brief Don't show last quit message in NickServ INFO. */
NI_HIDE_QUIT = 0x00000200
# /*! \brief SVSNICK in 20 seconds instead of 60. */
NI_ENFORCEQUICK = 0x00000400
# /*! \brief Don't add user to channel access lists. */
NI_NOOP = 0x00000800
NI_IRCOP = 0x00001000
#/*! \brief Only a services admin can SETPASS this nick. */
NI_MARKED = 0x00002000
#/*! \brief Nobody can SENDPASS this nick. */
NI_NOSENDPASS = 0x00004000
#/*! \brief Activate NickServ AUTOJOIN functions. */
NI_AUTOJOIN = 0x00008000
#/* dont op/voice user in channels on identify */
NI_AUTOPROMOTE = 0x00010000
#/*! \brief This nick (and its links) cannot be used. */
NI_SUSPENDED = 0x10000000

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

LANG_EN_US = 0
LANG_JA_JIS= 1
LANG_JA_EUC= 2
LANG_JA_SJIS =   3
LANG_ES=     4
LANG_PT=     5
LANG_FR=     6
LANG_TR=     7
LANG_IT=     8
LANG_PSYCHO= 9
LANG_DE=     10
LANG_DK=     11
LANG_SE=     12

def main():
    f = open('services.db', 'w')
    db = MySQLdb.connect("localhost", "services", "services", "services")
    cursor = db.cursor(cursorclass=MySQLdb.cursors.DictCursor)

    write_header(f)
    write_nicks(cursor, f)
    write_nick_links(cursor, f)
    write_nick_access(cursor, f)
    write_footer(f)
    
    f.close()

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


def write_footer(f):
    f.write("GDBV 3\n")
    f.write("KID 0\n")
    f.write("XID 0\n")
    f.write("QID 0\n")
    f.write("DE 1 0 0 0 0 0\n")

if __name__ == "__main__":
    main()
