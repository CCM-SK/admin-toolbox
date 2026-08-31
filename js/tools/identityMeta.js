import { $, escapeHtml, downloadText } from '../utils.js';

const WELL_KNOWN_SIDS = new Map([
  [
    'S-1-0-0',
    {
      name: 'NULL SID',
      category: 'Universal',
      scope: 'Universal',
      description:
        'A SID with no members. Commonly used when an identity is unknown or unavailable.'
    }
  ],

  [
    'S-1-1-0',
    {
      name: 'Everyone',
      category: 'Universal',
      scope: 'Universal',
      description:
        'A group that includes all users.'
    }
  ],

  [
    'S-1-2-0',
    {
      name: 'LOCAL',
      category: 'Universal',
      scope: 'Universal',
      description:
        'Users who log on through a locally connected terminal.'
    }
  ],

  [
    'S-1-2-1',
    {
      name: 'CONSOLE LOGON',
      category: 'Logon',
      scope: 'Windows',
      description:
        'Users logged on to the physical console.'
    }
  ],

  [
    'S-1-3-0',
    {
      name: 'CREATOR OWNER',
      category: 'Object placeholder',
      scope: 'Windows',
      description:
        'Placeholder SID used in inheritable ACEs and replaced with the SID of the object creator during inheritance.'
    }
  ],

  [
    'S-1-3-1',
    {
      name: 'CREATOR GROUP',
      category: 'Object placeholder',
      scope: 'Windows',
      description:
        'Placeholder SID replaced by the creator’s primary group SID when an inheritable ACE is applied.'
    }
  ],

  [
    'S-1-3-2',
    {
      name: 'OWNER SERVER',
      category: 'Object placeholder',
      scope: 'Windows',
      description:
        'Creator/server-related placeholder SID.'
    }
  ],

  [
    'S-1-3-3',
    {
      name: 'GROUP SERVER',
      category: 'Object placeholder',
      scope: 'Windows',
      description:
        'Creator/group-server placeholder SID.'
    }
  ],

  [
    'S-1-3-4',
    {
      name: 'OWNER RIGHTS',
      category: 'Object placeholder',
      scope: 'Windows',
      description:
        'SID used to identify the owner-rights trustee in security descriptors.'
    }
  ],

  [
    'S-1-5-1',
    {
      name: 'DIALUP',
      category: 'Logon',
      scope: 'Windows',
      description:
        'Group identity associated with users who log on using a dial-up connection.'
    }
  ],

  [
    'S-1-5-2',
    {
      name: 'NETWORK',
      category: 'Logon',
      scope: 'Windows',
      description:
        'Group identity added to a token for a network logon.'
    }
  ],

  [
    'S-1-5-3',
    {
      name: 'BATCH',
      category: 'Logon',
      scope: 'Windows',
      description:
        'Group identity associated with batch logons, such as scheduled tasks.'
    }
  ],

  [
    'S-1-5-4',
    {
      name: 'INTERACTIVE',
      category: 'Logon',
      scope: 'Windows',
      description:
        'Group identity associated with interactive logons.'
    }
  ],

  [
    'S-1-5-6',
    {
      name: 'SERVICE',
      category: 'Logon',
      scope: 'Windows',
      description:
        'Group identity associated with processes logged on as a service.'
    }
  ],

  [
    'S-1-5-7',
    {
      name: 'ANONYMOUS LOGON',
      category: 'Logon',
      scope: 'Windows',
      description:
        'Identity used for anonymous or null-session logons.'
    }
  ],

  [
    'S-1-5-8',
    {
      name: 'PROXY',
      category: 'Authentication',
      scope: 'Windows',
      description:
        'Proxy identity. Modern Windows does not normally use this SID.'
    }
  ],

  [
    'S-1-5-9',
    {
      name: 'ENTERPRISE DOMAIN CONTROLLERS',
      category: 'Active Directory',
      scope: 'Forest',
      description:
        'Group containing domain controllers in the forest.'
    }
  ],

  [
    'S-1-5-10',
    {
      name: 'SELF',
      category: 'Active Directory',
      scope: 'Windows / Active Directory',
      description:
        'Placeholder used in ACLs for a user, group, or computer object. During access checks it represents the security principal associated with the object.'
    }
  ],

  [
    'S-1-5-11',
    {
      name: 'Authenticated Users',
      category: 'Authentication',
      scope: 'Windows',
      description:
        'Group containing security principals that have been authenticated.'
    }
  ],

  [
    'S-1-5-12',
    {
      name: 'RESTRICTED CODE',
      category: 'Restricted token',
      scope: 'Windows',
      description:
        'Identity associated with a restricted security context.'
    }
  ],

  [
    'S-1-5-13',
    {
      name: 'TERMINAL SERVER USER',
      category: 'Remote access',
      scope: 'Windows',
      description:
        'Group identity associated with users signing in through Terminal Services / Remote Desktop Services.'
    }
  ],

  [
    'S-1-5-14',
    {
      name: 'REMOTE INTERACTIVE LOGON',
      category: 'Remote access',
      scope: 'Windows',
      description:
        'Group identity associated with remote interactive logons such as Remote Desktop.'
    }
  ],

  [
    'S-1-5-15',
    {
      name: 'THIS ORGANIZATION',
      category: 'Active Directory',
      scope: 'Active Directory',
      description:
        'Group identity representing authenticated users from the same organization.'
    }
  ],

  [
    'S-1-5-17',
    {
      name: 'IUSR',
      category: 'IIS',
      scope: 'Windows',
      description:
        'Built-in identity associated with the default IIS anonymous user.'
    }
  ],

  [
    'S-1-5-18',
    {
      name: 'NT AUTHORITY\\SYSTEM',
      category: 'Service account',
      scope: 'Local computer',
      description:
        'LocalSystem identity used by Windows and services configured to run as LocalSystem.'
    }
  ],

  [
    'S-1-5-19',
    {
      name: 'NT AUTHORITY\\LOCAL SERVICE',
      category: 'Service account',
      scope: 'Local computer',
      description:
        'Low-privilege local service identity with limited local privileges.'
    }
  ],

  [
    'S-1-5-20',
    {
      name: 'NT AUTHORITY\\NETWORK SERVICE',
      category: 'Service account',
      scope: 'Local computer',
      description:
        'Service identity with limited local privileges that uses the computer identity for network authentication.'
    }
  ],

  [
    'S-1-5-113',
    {
      name: 'NT AUTHORITY\\Local account',
      category: 'Account classification',
      scope: 'Windows',
      description:
        'Identity added to a token for a local account.'
    }
  ],

  [
    'S-1-5-114',
    {
      name: 'NT AUTHORITY\\Local account and member of Administrators group',
      category: 'Account classification',
      scope: 'Windows',
      description:
        'Identity added to a token when a local account is also a member of the built-in Administrators group.'
    }
  ],

  [
    'S-1-5-32-544',
    {
      name: 'BUILTIN\\Administrators',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Built-in local administrators group.'
    }
  ],

  [
    'S-1-5-32-545',
    {
      name: 'BUILTIN\\Users',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Built-in local users group.'
    }
  ],

  [
    'S-1-5-32-546',
    {
      name: 'BUILTIN\\Guests',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Built-in local guests group.'
    }
  ],

  [
    'S-1-5-32-547',
    {
      name: 'BUILTIN\\Power Users',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Built-in group historically associated with elevated user capabilities.'
    }
  ],

  [
    'S-1-5-32-548',
    {
      name: 'BUILTIN\\Account Operators',
      category: 'BUILTIN group',
      scope: 'Domain controller',
      description:
        'Built-in group for account-management operations.'
    }
  ],

  [
    'S-1-5-32-549',
    {
      name: 'BUILTIN\\Server Operators',
      category: 'BUILTIN group',
      scope: 'Domain controller',
      description:
        'Built-in group for server-operating and administrative tasks.'
    }
  ],

  [
    'S-1-5-32-550',
    {
      name: 'BUILTIN\\Print Operators',
      category: 'BUILTIN group',
      scope: 'Domain controller',
      description:
        'Built-in group for printer and print-queue administration.'
    }
  ],

  [
    'S-1-5-32-551',
    {
      name: 'BUILTIN\\Backup Operators',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Built-in group associated with backup and restore privileges.'
    }
  ],

  [
    'S-1-5-32-552',
    {
      name: 'BUILTIN\\Replicator',
      category: 'BUILTIN group',
      scope: 'Windows',
      description:
        'Built-in group associated with legacy replication operations.'
    }
  ],

  [
    'S-1-5-32-554',
    {
      name: 'BUILTIN\\Pre-Windows 2000 Compatible Access',
      category: 'BUILTIN group',
      scope: 'Active Directory',
      description:
        'Backward-compatibility group providing read access to specified users and groups.'
    }
  ],

  [
    'S-1-5-32-555',
    {
      name: 'BUILTIN\\Remote Desktop Users',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Members are granted the ability to sign in remotely through Remote Desktop Services.'
    }
  ],

  [
    'S-1-5-32-556',
    {
      name: 'BUILTIN\\Network Configuration Operators',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Group associated with selected network-configuration privileges.'
    }
  ],

  [
    'S-1-5-32-557',
    {
      name: 'BUILTIN\\Incoming Forest Trust Builders',
      category: 'BUILTIN group',
      scope: 'Active Directory',
      description:
        'Group associated with creating incoming forest trusts.'
    }
  ],

  [
    'S-1-5-32-558',
    {
      name: 'BUILTIN\\Performance Monitor Users',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Group associated with remote performance monitoring.'
    }
  ],

  [
    'S-1-5-32-559',
    {
      name: 'BUILTIN\\Performance Log Users',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Group associated with scheduling and collecting performance logs.'
    }
  ],

  [
    'S-1-5-32-560',
    {
      name: 'BUILTIN\\Windows Authorization Access Group',
      category: 'BUILTIN group',
      scope: 'Active Directory',
      description:
        'Group with access to selected authorization information such as tokenGroupsGlobalAndUniversal.'
    }
  ],

  [
    'S-1-5-32-561',
    {
      name: 'BUILTIN\\Terminal Server License Servers',
      category: 'BUILTIN group',
      scope: 'Remote Desktop Services',
      description:
        'Group for Terminal Server / Remote Desktop licensing servers.'
    }
  ],

  [
    'S-1-5-32-562',
    {
      name: 'BUILTIN\\Distributed COM Users',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Group used for selected Distributed COM access controls.'
    }
  ],

  [
    'S-1-5-32-568',
    {
      name: 'BUILTIN\\IIS_IUSRS',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Built-in IIS worker-process user group.'
    }
  ],

  [
    'S-1-5-32-569',
    {
      name: 'BUILTIN\\Cryptographic Operators',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Group associated with selected cryptographic operations.'
    }
  ],

  [
    'S-1-5-32-571',
    {
      name: 'BUILTIN\\Allowed RODC Password Replication Group',
      category: 'BUILTIN / Active Directory',
      scope: 'Active Directory',
      description:
        'Group whose members may have passwords replicated to read-only domain controllers.'
    }
  ],

  [
    'S-1-5-32-572',
    {
      name: 'BUILTIN\\Denied RODC Password Replication Group',
      category: 'BUILTIN / Active Directory',
      scope: 'Active Directory',
      description:
        'Group whose members are denied password replication to read-only domain controllers.'
    }
  ],

  [
    'S-1-5-32-573',
    {
      name: 'BUILTIN\\Event Log Readers',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Group whose members can read event logs.'
    }
  ],

  [
    'S-1-5-32-574',
    {
      name: 'BUILTIN\\Certificate Service DCOM Access',
      category: 'BUILTIN group',
      scope: 'Local computer / AD CS',
      description:
        'Group whose members can connect to certification authorities using DCOM.'
    }
  ],

  [
    'S-1-5-32-575',
    {
      name: 'BUILTIN\\RDS Remote Access Servers',
      category: 'BUILTIN group',
      scope: 'Remote Desktop Services',
      description:
        'Group for servers providing Remote Desktop remote-access resources.'
    }
  ],

  [
    'S-1-5-32-576',
    {
      name: 'BUILTIN\\RDS Endpoint Servers',
      category: 'BUILTIN group',
      scope: 'Remote Desktop Services',
      description:
        'Group for servers hosting Remote Desktop sessions and virtual applications.'
    }
  ],

  [
    'S-1-5-32-577',
    {
      name: 'BUILTIN\\RDS Management Servers',
      category: 'BUILTIN group',
      scope: 'Remote Desktop Services',
      description:
        'Group for servers performing routine Remote Desktop Services administration.'
    }
  ],

  [
    'S-1-5-32-578',
    {
      name: 'BUILTIN\\Hyper-V Administrators',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Built-in group with extensive Hyper-V administrative privileges.'
    }
  ],

  [
    'S-1-5-32-579',
    {
      name: 'BUILTIN\\Access Control Assistance Operators',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Group whose members can remotely query authorization attributes and resource permissions.'
    }
  ],

  [
    'S-1-5-32-580',
    {
      name: 'BUILTIN\\Remote Management Users',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Group associated with selected Windows Remote Management and WMI access.'
    }
  ],

  [
    'S-1-5-32-581',
    {
      name: 'BUILTIN\\Default System Managed Group',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'System-managed built-in group associated with the default system-managed account.'
    }
  ],

  [
    'S-1-5-32-582',
    {
      name: 'BUILTIN\\Storage Replica Administrators',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Built-in group for Storage Replica administration.'
    }
  ],

  [
    'S-1-5-32-583',
    {
      name: 'BUILTIN\\Device Owners',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Built-in group associated with device-owner configuration rights.'
    }
  ],

  [
    'S-1-5-32-584',
    {
      name: 'BUILTIN\\User Mode Hardware Operators',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Built-in group associated with access to user-mode mapper drivers.'
    }
  ],

  [
    'S-1-5-32-585',
    {
      name: 'BUILTIN\\OpenSSH Users',
      category: 'BUILTIN group',
      scope: 'Local computer',
      description:
        'Built-in group for users permitted to access the computer through OpenSSH.'
    }
  ],

  [
    'S-1-5-64-10',
    {
      name: 'NTLM Authentication',
      category: 'Authentication package',
      scope: 'Windows',
      description:
        'SID used when NTLM authenticates the client.'
    }
  ],

  [
    'S-1-5-64-14',
    {
      name: 'SChannel Authentication',
      category: 'Authentication package',
      scope: 'Windows',
      description:
        'SID used when the Schannel authentication package authenticates the client.'
    }
  ],

  [
    'S-1-5-64-21',
    {
      name: 'Digest Authentication',
      category: 'Authentication package',
      scope: 'Windows',
      description:
        'SID used when the Digest authentication package authenticates the client.'
    }
  ],

  [
    'S-1-5-65-1',
    {
      name: 'THIS ORGANIZATION CERTIFICATE',
      category: 'Authentication / Kerberos',
      scope: 'Active Directory',
      description:
        'SID indicating a Kerberos service ticket PAC containing the relevant organization-certificate credential information.'
    }
  ],

  [
    'S-1-5-80',
    {
      name: 'NT SERVICE',
      category: 'Service SID',
      scope: 'Local computer',
      description:
        'Prefix used to construct per-service SIDs.'
    }
  ],

  [
    'S-1-5-80-0',
    {
      name: 'NT SERVICE\\ALL SERVICES',
      category: 'Service SID',
      scope: 'Local computer',
      description:
        'Group containing all service processes configured on the system. Membership is controlled by Windows.'
    }
  ],

  [
    'S-1-5-83-0',
    {
      name: 'NT VIRTUAL MACHINE\\Virtual Machines',
      category: 'Hyper-V',
      scope: 'Local computer',
      description:
        'Built-in group created when the Hyper-V role is installed.'
    }
  ],

  [
    'S-1-15-2-1',
    {
      name: 'ALL APPLICATION PACKAGES',
      category: 'Application package',
      scope: 'Local computer',
      description:
        'Security principal representing all applications running in an app-package context.'
    }
  ],

  [
    'S-1-18-1',
    {
      name: 'AUTHENTICATION AUTHORITY ASSERTED IDENTITY',
      category: 'Authentication authority',
      scope: 'Windows',
      description:
        'Identity asserted by an authentication authority based on proof of possession of client credentials.'
    }
  ],

  [
    'S-1-18-2',
    {
      name: 'SERVICE ASSERTED IDENTITY',
      category: 'Authentication authority',
      scope: 'Windows',
      description:
        'Identity asserted by a service.'
    }
  ],

  [
    'S-1-18-3',
    {
      name: 'FRESH PUBLIC KEY IDENTITY',
      category: 'Authentication authority',
      scope: 'Windows',
      description:
        'Identity based on proof of current possession of client public-key credentials.'
    }
  ],

  [
    'S-1-18-4',
    {
      name: 'KEY TRUST IDENTITY',
      category: 'Authentication authority',
      scope: 'Windows',
      description:
        'Identity based on proof of possession of public-key credentials through the key-trust mechanism.'
    }
  ],

  [
    'S-1-18-5',
    {
      name: 'KEY PROPERTY MFA',
      category: 'Authentication authority',
      scope: 'Windows',
      description:
        'Identity indicating that the key-trust object has the multifactor-authentication property.'
    }
  ],

  [
    'S-1-18-6',
    {
      name: 'KEY PROPERTY ATTESTATION',
      category: 'Authentication authority',
      scope: 'Windows',
      description:
        'Identity indicating that the key-trust object has the attestation property.'
    }
  ],

  [
    'S-1-16-0',
    {
      name: 'Untrusted',
      category: 'Integrity level',
      scope: 'Windows',
      description:
        'Untrusted mandatory integrity level.'
    }
  ],

  [
    'S-1-16-4096',
    {
      name: 'Low',
      category: 'Integrity level',
      scope: 'Windows',
      description:
        'Low mandatory integrity level.'
    }
  ],

  [
    'S-1-16-8192',
    {
      name: 'Medium',
      category: 'Integrity level',
      scope: 'Windows',
      description:
        'Medium mandatory integrity level.'
    }
  ],

  [
    'S-1-16-8448',
    {
      name: 'Medium Plus',
      category: 'Integrity level',
      scope: 'Windows',
      description:
        'Medium-plus mandatory integrity level.'
    }
  ],

  [
    'S-1-16-12288',
    {
      name: 'High',
      category: 'Integrity level',
      scope: 'Windows',
      description:
        'High mandatory integrity level.'
    }
  ],

  [
    'S-1-16-16384',
    {
      name: 'System',
      category: 'Integrity level',
      scope: 'Windows',
      description:
        'System mandatory integrity level.'
    }
  ],

  [
    'S-1-16-20480',
    {
      name: 'Protected Process',
      category: 'Integrity level',
      scope: 'Windows',
      description:
        'Protected-process mandatory integrity level.'
    }
  ],

  [
    'S-1-16-28672',
    {
      name: 'Secure Process',
      category: 'Integrity level',
      scope: 'Windows',
      description:
        'Secure-process mandatory integrity level.'
    }
  ]
]);

const DOMAIN_RIDS = new Map([
  [
    500,
    {
      name: 'Administrator',
      category: 'Domain account',
      description:
        'Built-in administrative account for a domain or local machine namespace.'
    }
  ],

  [
    501,
    {
      name: 'Guest',
      category: 'Domain account',
      description:
        'Built-in guest account.'
    }
  ],

  [
    502,
    {
      name: 'KRBTGT',
      category: 'Domain account',
      description:
        'Key Distribution Center service account used by Active Directory domain controllers.'
    }
  ],

  [
    512,
    {
      name: 'Domain Admins',
      category: 'Domain group',
      description:
        'Global group whose members are authorized to administer the domain.'
    }
  ],

  [
    513,
    {
      name: 'Domain Users',
      category: 'Domain group',
      description:
        'Global group containing user accounts in the domain.'
    }
  ],

  [
    514,
    {
      name: 'Domain Guests',
      category: 'Domain group',
      description:
        'Global group associated with domain guest accounts.'
    }
  ],

  [
    515,
    {
      name: 'Domain Computers',
      category: 'Domain group',
      description:
        'Global group containing computers joined to the domain, excluding domain controllers.'
    }
  ],

  [
    516,
    {
      name: 'Domain Controllers',
      category: 'Domain group',
      description:
        'Global group containing domain controllers in the domain.'
    }
  ],

  [
    517,
    {
      name: 'Cert Publishers',
      category: 'Domain group',
      description:
        'Group containing computers that host an enterprise certification authority.'
    }
  ],

  [
    518,
    {
      name: 'Schema Admins',
      category: 'Domain group',
      description:
        'Group authorized to make Active Directory schema changes.'
    }
  ],

  [
    519,
    {
      name: 'Enterprise Admins',
      category: 'Forest group',
      description:
        'Forest-level administrative group.'
    }
  ],

  [
    520,
    {
      name: 'Group Policy Creator Owners',
      category: 'Domain group',
      description:
        'Group authorized to create Group Policy Objects in Active Directory.'
    }
  ],

  [
    521,
    {
      name: 'Read-only Domain Controllers',
      category: 'Domain group',
      description:
        'Group containing read-only domain controllers.'
    }
  ],

  [
    522,
    {
      name: 'Cloneable Domain Controllers',
      category: 'Domain group',
      description:
        'Group containing domain controllers that are eligible for cloning.'
    }
  ],

  [
    525,
    {
      name: 'Protected Users',
      category: 'Domain group',
      description:
        'Group whose members receive additional authentication protections.'
    }
  ],

  [
    526,
    {
      name: 'Key Admins',
      category: 'Domain group',
      description:
        'Group intended for trusted administrators responsible for modifying key-related attributes.'
    }
  ],

  [
    527,
    {
      name: 'Enterprise Key Admins',
      category: 'Forest group',
      description:
        'Forest-level key-administration group.'
    },

  ],

  [
    553,
    {
      name: 'RAS and IAS Servers',
      category: 'Domain group',
      description:
        'Group associated with Routing and Remote Access / Internet Authentication Service servers.'
    }
  ]
]);

const BUILTIN_RIDS = new Map([
  [544, 'Administrators'],
  [545, 'Users'],
  [546, 'Guests'],
  [547, 'Power Users'],
  [548, 'Account Operators'],
  [549, 'Server Operators'],
  [550, 'Print Operators'],
  [551, 'Backup Operators'],
  [552, 'Replicator'],
  [554, 'Pre-Windows 2000 Compatible Access'],
  [555, 'Remote Desktop Users'],
  [556, 'Network Configuration Operators'],
  [557, 'Incoming Forest Trust Builders'],
  [558, 'Performance Monitor Users'],
  [559, 'Performance Log Users'],
  [560, 'Windows Authorization Access Group'],
  [561, 'Terminal Server License Servers'],
  [562, 'Distributed COM Users'],
  [568, 'IIS_IUSRS'],
  [569, 'Cryptographic Operators'],
  [571, 'Allowed RODC Password Replication Group'],
  [572, 'Denied RODC Password Replication Group'],
  [573, 'Event Log Readers'],
  [574, 'Certificate Service DCOM Access'],
  [575, 'RDS Remote Access Servers'],
  [576, 'RDS Endpoint Servers'],
  [577, 'RDS Management Servers'],
  [578, 'Hyper-V Administrators'],
  [579, 'Access Control Assistance Operators'],
  [580, 'Remote Management Users'],
  [581, 'Default System Managed Group'],
  [582, 'Storage Replica Administrators'],
  [583, 'Device Owners'],
  [584, 'User Mode Hardware Operators'],
  [585, 'OpenSSH Users']
]);

const SID_PATTERNS = [
  {
    id: 'logon-session',
    category: 'Logon session',
    match: subs =>
      subs.length === 3 &&
      subs[0] === 5 &&
      subs[1] === 5,

    resolve: subs => ({
      resolutionType: 'pattern',
      name: 'LOGON SESSION',
      category: 'Logon session',
      scope: 'Windows',
      description:
        'Per-logon-session SID. The final components vary between logon sessions.',
      details: {
        sessionIdentifier: subs.slice(2)
      }
    })
  },

  {
    id: 'domain-sid',
    category: 'Domain SID',
    match: subs =>
      subs.length === 5 &&
      subs[0] === 21,

    resolve: subs => {
      const rid = subs[4];
      const entry = DOMAIN_RIDS.get(rid);

      if (entry) {
        return {
          resolutionType: 'contextual',
          name: entry.name,
          category: entry.category,
          scope: 'Active Directory',
          description: entry.description,
          details: {
            domainSid: `S-1-5-21-${subs[1]}-${subs[2]}-${subs[3]}`,
            relativeId: rid,
            note:
              'The RID has a conventional well-known meaning, but the actual domain name is not encoded in the SID.'
          }
        };
      }

      return {
        resolutionType: 'pattern',
        name: null,
        category: 'Domain SID',
        scope: 'Active Directory',
        description:
          'A domain-specific SID. The final value is a RID identifying an object relative to this domain.',
        details: {
          domainSid: `S-1-5-21-${subs[1]}-${subs[2]}-${subs[3]}`,
          relativeId: rid
        }
      };
    }
  },

  {
    id: 'builtin-domain',
    category: 'BUILTIN group',
    match: subs =>
      subs.length === 2 &&
      subs[0] === 32,

    resolve: subs => {
      const rid = subs[1];
      const name = BUILTIN_RIDS.get(rid);

      if (!name) {
        return {
          resolutionType: 'pattern',
          name: null,
          category: 'BUILTIN group',
          scope: 'Local computer',
          description:
            'A SID in the Windows BUILTIN security domain with an unrecognized RID.',
          details: {
            relativeId: rid
          }
        };
      }

      return {
        resolutionType: 'contextual',
        name: `BUILTIN\\${name}`,
        category: 'BUILTIN group',
        scope: 'Local computer',
        description:
          'A built-in Windows local group identified by a well-known BUILTIN RID.',
        details: {
          relativeId: rid
        }
      };
    }
  },

  {
    id: 'nt-service-account',
    category: 'Service SID',
    match: subs =>
      subs.length >= 2 &&
      subs[0] === 80,

    resolve: subs => {
      const serviceParts = subs.slice(1);

      return {
        resolutionType: 'pattern',
        name: null,
        category: 'Service SID',
        scope: 'Local computer',
        description:
          'An NT SERVICE SID. Service-specific SIDs identify individual Windows services, but the service name cannot generally be reconstructed from the numeric SID alone.',
        details: {
          serviceSidComponents: serviceParts
        }
      };
    }
  },

  {
    id: 'hyperv-virtual-machine',
    category: 'Hyper-V',
    match: subs =>
      subs.length >= 2 &&
      subs[0] === 83,

    resolve: subs => ({
      resolutionType: 'pattern',
      name: null,
      category: 'Hyper-V',
      scope: 'Local computer',
      description:
        'SID from the Windows Hyper-V security identifier family.',
      details: {
        components: subs.slice(1)
      }
    })
  },

  {
    id: 'capability',
    category: 'Capability',
    match: subs =>
      subs.length >= 2 &&
      subs[0] === 15 &&
      subs[1] === 3,

    resolve: subs => ({
      resolutionType: 'pattern',
      name: null,
      category: 'Capability',
      scope: 'Windows',
      description:
        'Capability SID. Capability SIDs are unique immutable identifiers for application capabilities. The capability name is not encoded as plain text in the SID.',
      details: {
        capabilityComponents: subs.slice(2)
      }
    })
  },

  {
    id: 'application-package-authority',
    category: 'Application package',
    match: subs =>
      subs.length >= 2 &&
      subs[0] === 15 &&
      subs[1] === 2,

    resolve: subs => ({
      resolutionType: 'pattern',
      name:
        subs.length === 3 && subs[2] === 1
          ? 'ALL APPLICATION PACKAGES'
          : null,
      category: 'Application package',
      scope: 'Windows',
      description:
        'SID from the application-package security authority.',
      details: {
        components: subs.slice(2)
      }
    })
  },

  {
    id: 'integrity-level',
    category: 'Integrity level',
    match: subs =>
      subs.length === 2 &&
      subs[0] === 16,

    resolve: subs => {
      const sid = `S-1-16-${subs[1]}`;
      const exact = WELL_KNOWN_SIDS.get(sid);

      if (exact) {
        return {
          resolutionType: 'exact',
          ...exact
        };
      }

      return {
        resolutionType: 'pattern',
        name: null,
        category: 'Integrity level',
        scope: 'Windows',
        description:
          'SID from the mandatory integrity-level authority.',
        details: {
          integrityRid: subs[1]
        }
      };
    }
  },

  {
    id: 'restricted-services',
    category: 'Restricted services',
    match: subs =>
      subs.length >= 1 &&
      subs[0] === 99,

    resolve: subs => ({
      resolutionType: 'pattern',
      name: 'Restricted Services',
      category: 'Restricted services',
      scope: 'Windows',
      description:
        'SID from the Windows restricted-services SID family.',
      details: {
        components: subs.slice(1)
      }
    })
  },

  {
    id: 'authentication-authority',
    category: 'Authentication authority',
    match: subs =>
      subs.length >= 2 &&
      subs[0] === 18,

    resolve: subs => {
      const sid = `S-1-18-${subs.slice(1).join('-')}`;
      const exact = WELL_KNOWN_SIDS.get(sid);

      if (exact) {
        return {
          resolutionType: 'exact',
          ...exact
        };
      }

      return {
        resolutionType: 'pattern',
        name: null,
        category: 'Authentication authority',
        scope: 'Windows',
        description:
          'SID from the authentication-authority security namespace.',
        details: {
          components: subs.slice(1)
        }
      };
    }
  },

  {
    id: 'nt-authority-prefix',
    category: 'NT AUTHORITY',
    match: subs =>
      subs.length === 0,

    resolve: () => ({
      resolutionType: 'pattern',
      name: 'NT AUTHORITY',
      category: 'Security authority',
      scope: 'Windows',
      description:
        'Windows NT security authority prefix.'
    })
  }
];

export function renderIdentityMeta(app) {
  app.innerHTML = `
    <section class="card">
      <h2>SID / GUID / identity decoder</h2>
      <p class="small">
        Recognizes Windows SIDs, GUIDs, UUID byte strings, and common GUID representations.
        Processing is entirely local.
      </p>

      <label for="identityInput">Value</label>
      <textarea
        id="identityInput"
        class="mono"
        style="min-height:180px"
        placeholder="Examples:
S-1-5-21-1111111111-2222222222-3333333333-1107
S-1-5-18
S-1-5-32-544
550e8400-e29b-41d4-a716-446655440000
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      ></textarea>

      <div class="row" style="margin-top:10px">
        <button class="btn primary" id="identityDecode">Decode</button>
        <button class="btn" id="identityClear">Clear</button>
        <button class="btn" id="identityExport">Export result</button>
      </div>
    </section>

    <section class="card" id="identityResult" hidden></section>
  `;

  let last = null;

  $('#identityDecode').onclick = () => {
    last = decode($('#identityInput').value.trim());
    render(last);
  };

  $('#identityClear').onclick = () => {
    $('#identityInput').value = '';
    $('#identityResult').hidden = true;
    last = null;
    $('#identityInput').focus();
  };

  $('#identityExport').onclick = () => {
    if (!last) {
      last = decode($('#identityInput').value.trim());
    }

    downloadText(
      'identity-decoder.json',
      JSON.stringify(last, null, 2),
      'application/json;charset=utf-8'
    );
  };

  function decode(v) {
    const out = {
      input: v,
      matches: []
    };

    if (!v) {
      return out;
    }

    const sid = parseSid(v);
    if (sid) {
      out.matches.push(sid);
    }

    const guid = parseGuid(v);
    if (guid) {
      out.matches.push(guid);
    }

    const bytes = parseBytes(v);

    if (bytes && bytes.length === 16) {
      const standard = bytesToGuid(bytes, false);
      const mixed = bytesToGuid(bytes, true);

      out.matches.push({
        type: 'GUID byte string',
        standardGuid: standard,
        littleEndianGuid: mixed,
        rawBytes: Array.from(bytes)
          .map(b => b.toString(16).padStart(2, '0'))
          .join(' ')
      });
    }

    if (!out.matches.length) {
      out.error = 'No recognized SID/GUID representation.';
    }

    return out;
  }

  function parseSid(v) {
  const input = v.trim();
  const m = input.match(
    /^S-(\d+)-(\d+|0x[0-9a-fA-F]+)((?:-\d+)+)$/i
  );

  if (!m) {
    return null;
  }

  const revision = Number(m[1]);

  if (
    !Number.isSafeInteger(revision) ||
    revision < 0
  ) {
    return null;
  }

  let authority;

  try {
    authority = BigInt(
      m[2].toLowerCase().startsWith('0x')
        ? m[2]
        : m[2]
    );
  } catch {
    return null;
  }

  const MAX_AUTHORITY = (1n << 48n) - 1n;

  if (
    authority < 0n ||
    authority > MAX_AUTHORITY
  ) {
    return null;
  }

  const subs = m[3]
    .slice(1)
    .split('-')
    .map(Number);

  if (
    subs.length < 1 ||
    subs.length > 8
  ) {
    return null;
  }

  const MAX_SUBAUTHORITY = 0xffffffff;

  if (
    subs.some(
      x =>
        !Number.isSafeInteger(x) ||
        x < 0 ||
        x > MAX_SUBAUTHORITY
    )
  ) {
    return null;
  }

  const canonicalSid =
    `S-${revision}-${authority.toString()}-${subs.join('-')}`;

  const exact = WELL_KNOWN_SIDS.get(canonicalSid);

  if (exact) {
    return {
      type: 'Windows SID',

      sid: canonicalSid,

      revision,

      identifierAuthority:
        authority.toString(),

      subAuthorities: subs,

      relativeId: subs.at(-1),

      resolutionType: 'exact',

      name: exact.name,

      category: exact.category,

      scope: exact.scope,

      description: exact.description,

      wellKnownMeaning: exact.name,

      displayName: exact.name,

      resolutionSource:
        'local-static-sid-map',

      isWellKnown: true,

      isContextual: false,

      isPattern: false,

      domainIdentifier:
        isDomainSid(subs)
          ? subs.slice(1, -1)
          : []
    };
  }

  for (const pattern of SID_PATTERNS) {
    if (!pattern.match(subs)) {
      continue;
    }

    const resolved =
      pattern.resolve(subs);

    if (!resolved) {
      continue;
    }

    return {
      type: 'Windows SID',

      sid: canonicalSid,

      revision,

      identifierAuthority:
        authority.toString(),

      subAuthorities: subs,

      relativeId: subs.at(-1),

      ...resolved,

      wellKnownMeaning:
        resolved.resolutionType === 'exact'
          ? resolved.name
          : null,

      displayName:
        resolved.name || null,

      resolutionSource:
        resolved.resolutionType === 'contextual'
          ? 'local-contextual-rid-map'
          : 'local-sid-pattern',

      isWellKnown:
        resolved.resolutionType === 'exact',

      isContextual:
        resolved.resolutionType === 'contextual',

      isPattern:
        resolved.resolutionType === 'pattern',

      domainIdentifier:
        isDomainSid(subs)
          ? subs.slice(1, -1)
          : []
    };
  }

  return {
    type: 'Windows SID',

    sid: canonicalSid,

    revision,

    identifierAuthority:
      authority.toString(),

    subAuthorities: subs,

    relativeId: subs.at(-1),

    resolutionType: 'unknown',

    name: null,

    category: 'Unknown',

    scope: 'Unknown',

    description:
      'Valid SID structure, but no matching local knowledge-base entry or pattern was found.',

    wellKnownMeaning: null,

    displayName: null,

    resolutionSource: null,

    isWellKnown: false,

    isContextual: false,

    isPattern: false,

    domainIdentifier:
      isDomainSid(subs)
        ? subs.slice(1, -1)
        : []
  };
}

function isDomainSid(subs) {
  return (
    subs.length === 5 &&
    subs[0] === 21
  );
}

function sidSummary(sidResult) {
  if (!sidResult) {
    return null;
  }

  if (sidResult.name) {
    return sidResult.name;
  }

  if (sidResult.resolutionType === 'pattern') {
    return `${sidResult.category}: pattern recognized`;
  }

  if (sidResult.resolutionType === 'unknown') {
    return 'Unknown Windows SID';
  }

  return null;
}

  function classifySidContext(
    revision,
    authority,
    subs,
    rid
  ) {
    if (revision !== 1 || authority !== 5) {
      return null;
    }
    if (subs.length === 2 && subs[0] === 32) {
      const meaning = BUILTIN_RIDS.get(rid);

      if (!meaning) {
        return null;
      }

      return {
        context: 'BUILTIN local group',
        meaning,
        displayName: `BUILTIN\\${meaning}`
      };
    }

    if (
      subs.length === 5 &&
      subs[0] === 21
    ) {
      const meaning = DOMAIN_RIDS.get(rid);

      if (!meaning) {
        return {
          context: 'Domain SID',
          meaning: null,
          displayName: null
        };
      }

      return {
        context: 'Domain account/group',
        meaning,
        displayName: `DOMAIN\\${meaning}`
      };
    }

    return null;
  }

  function isDomainSid(subs) {
    return (
      subs.length >= 5 &&
      subs[0] === 21
    );
  }

  function parseGuid(v) {
    const s = v.trim().replace(/[{}]/g, '');

    if (
      !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(
        s
      )
    ) {
      return null;
    }

    const hex = s
      .replaceAll('-', '')
      .toLowerCase();

    const bytes = hex
      .match(/../g)
      .map(x => parseInt(x, 16));

    return {
      type: 'GUID / UUID',
      canonical: s.toLowerCase(),
      uppercase: s.toUpperCase(),
      braced: `{${s.toUpperCase()}}`,
      hexBytes: bytes
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' '),
      registryByteOrder: toMixedEndian(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ')
    };
  }

  function parseBytes(v) {
    const compact = v
      .replace(/0x/gi, '')
      .replace(/[\s,;:-]/g, '');

    if (
      !/^[0-9a-fA-F]+$/.test(compact) ||
      compact.length % 2
    ) {
      return null;
    }

    const out = new Uint8Array(compact.length / 2);

    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(
        compact.slice(i * 2, i * 2 + 2),
        16
      );
    }

    return out;
  }

  function bytesToGuid(b, little) {
    const x = little
      ? toMixedEndian([...b])
      : [...b];

    const h = x
      .map(z => z.toString(16).padStart(2, '0'))
      .join('');

    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  function toMixedEndian(b) {
    return [
      b[3],
      b[2],
      b[1],
      b[0],
      b[5],
      b[4],
      b[7],
      b[6],
      ...b.slice(8)
    ];
  }

  function render(r) {
    const el = $('#identityResult');
    el.hidden = false;

    if (r.error) {
      el.innerHTML = `
        <p class="status warn">
          ${escapeHtml(r.error)}
        </p>
      `;
      return;
    }

    el.innerHTML = r.matches
      .map(
        m => `
          <div
            class="card"
            style="box-shadow:none;margin:0 0 12px;padding:14px"
          >
            <h3>${escapeHtml(m.type)}</h3>
            <pre class="mono">${escapeHtml(
              JSON.stringify(m, null, 2)
            )}</pre>
          </div>
        `
      )
      .join('');
  }
}