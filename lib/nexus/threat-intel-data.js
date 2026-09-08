"use strict";

// ---------------------------------------------------------------------------
//  Darknode Nexus -- Threat Intelligence Reference Data
// ---------------------------------------------------------------------------
//
//  Curated threat-actor profiles, malware families, IOC patterns,
//  threat feeds, ransomware groups, and notable attack campaigns.
//
//  Data sections:
//    1. THREAT_ACTORS       -- 45 entries  (APTs, cybercriminal groups, mercenaries)
//    2. MALWARE_FAMILIES    -- 43 entries  (RATs, stealers, loaders, wipers, C2 frameworks)
//    3. IOC_PATTERNS        -- 61 entries  (regex patterns for indicator extraction)
//    4. THREAT_FEEDS        -- 29 entries  (OSINT and commercial intelligence sources)
//    5. RANSOMWARE_GROUPS   -- 24 entries  (active and disrupted ransomware operations)
//    6. ATTACK_CAMPAIGNS    -- 18 entries  (significant historical cyber operations)
//
// ---------------------------------------------------------------------------

// ===================================================================
//  1. THREAT ACTORS  (40+)
//  Each entry: { name, aliases, origin, type, targets, motivation,
//                activeSince, notableCampaigns }
// ===================================================================

const THREAT_ACTORS = [
  // ---------------------------------------------------------------
  //  1  APT28 / Fancy Bear
  // ---------------------------------------------------------------
  {
    name: "APT28",
    aliases: [
      "Fancy Bear",
      "Sofacy",
      "Pawn Storm",
      "Sednit",
      "STRONTIUM",
      "Forest Blizzard",
      "Tsar Team",
      "Group 74",
      "TG-4127",
      "Snakemackerel"
    ],
    origin: "Russia",
    type: "nation-state",
    targets: [
      "government",
      "military",
      "defense",
      "media",
      "political organizations",
      "aerospace",
      "energy"
    ],
    motivation: "espionage",
    activeSince: 2004,
    notableCampaigns: [
      "DNC hack (2016)",
      "Bundestag attack (2015)",
      "WADA breach (2016)",
      "NotPetya precursor operations (2017)",
      "Georgia cyber operations (2008-2020)",
      "COVID-19 vaccine research targeting (2020)",
      "European Parliament phishing (2023)"
    ]
  },

  // ---------------------------------------------------------------
  //  2  APT29 / Cozy Bear
  // ---------------------------------------------------------------
  {
    name: "APT29",
    aliases: [
      "Cozy Bear",
      "The Dukes",
      "NOBELIUM",
      "Midnight Blizzard",
      "YTTRIUM",
      "CozyDuke",
      "Dark Halo",
      "UNC2452",
      "StellarParticle"
    ],
    origin: "Russia",
    type: "nation-state",
    targets: [
      "government",
      "think tanks",
      "diplomatic",
      "technology",
      "healthcare",
      "energy",
      "cloud service providers"
    ],
    motivation: "espionage",
    activeSince: 2008,
    notableCampaigns: [
      "SolarWinds supply chain attack (2020)",
      "DNC compromise (2015)",
      "COVID-19 vaccine espionage (2020)",
      "Microsoft 365 tenant compromise (2023)",
      "TeamCity CVE-2023-42793 exploitation (2023)",
      "European diplomatic phishing (2024)"
    ]
  },

  // ---------------------------------------------------------------
  //  3  APT1 / Comment Crew
  // ---------------------------------------------------------------
  {
    name: "APT1",
    aliases: [
      "Comment Crew",
      "Comment Panda",
      "PLA Unit 61398",
      "Byzantine Candor",
      "TG-8223",
      "GIF89a",
      "Shanghai Group"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "technology",
      "aerospace",
      "defense",
      "telecommunications",
      "energy",
      "manufacturing",
      "financial services"
    ],
    motivation: "espionage / intellectual property theft",
    activeSince: 2006,
    notableCampaigns: [
      "Mandiant APT1 report targets (2006-2013)",
      "Operation Shady RAT attribution",
      "RSA SecurID breach (2011)",
      "Fortune 500 industrial espionage"
    ]
  },

  // ---------------------------------------------------------------
  //  4  Lazarus Group
  // ---------------------------------------------------------------
  {
    name: "Lazarus Group",
    aliases: [
      "HIDDEN COBRA",
      "Guardians of Peace",
      "ZINC",
      "Diamond Sleet",
      "Labyrinth Chollima",
      "APT38",
      "Bluenoroff",
      "Andariel",
      "TraderTraitor",
      "Stardust Chollima"
    ],
    origin: "North Korea",
    type: "nation-state",
    targets: [
      "financial institutions",
      "cryptocurrency exchanges",
      "defense",
      "entertainment",
      "energy",
      "aerospace",
      "blockchain / DeFi"
    ],
    motivation: "financial gain / espionage / disruption",
    activeSince: 2009,
    notableCampaigns: [
      "Sony Pictures hack (2014)",
      "Bangladesh Bank SWIFT heist (2016)",
      "WannaCry ransomware (2017)",
      "Operation AppleJeus (2018-2024)",
      "Ronin Network theft $620M (2022)",
      "Atomic Wallet heist (2023)",
      "Bybit exchange compromise (2025)"
    ]
  },

  // ---------------------------------------------------------------
  //  5  APT41 / Double Dragon
  // ---------------------------------------------------------------
  {
    name: "APT41",
    aliases: [
      "Double Dragon",
      "Winnti Group",
      "BARIUM",
      "Brass Typhoon",
      "Wicked Panda",
      "Blackfly",
      "Grayfly",
      "Red Kelpy"
    ],
    origin: "China",
    type: "nation-state / cybercriminal hybrid",
    targets: [
      "healthcare",
      "gaming",
      "telecommunications",
      "technology",
      "government",
      "manufacturing",
      "education"
    ],
    motivation: "espionage / financial gain",
    activeSince: 2012,
    notableCampaigns: [
      "ShadowPad supply chain (2017)",
      "CCleaner supply chain (2017)",
      "ASUS Live Update compromise (2018)",
      "U.S. state government intrusions (2021-2022)",
      "Global telecom network infiltration (2019-2023)"
    ]
  },

  // ---------------------------------------------------------------
  //  6  Sandworm
  // ---------------------------------------------------------------
  {
    name: "Sandworm",
    aliases: [
      "Voodoo Bear",
      "IRIDIUM",
      "Seashell Blizzard",
      "TeleBots",
      "Quedagh",
      "BlackEnergy Group",
      "GRU Unit 74455",
      "Hades"
    ],
    origin: "Russia",
    type: "nation-state",
    targets: [
      "critical infrastructure",
      "energy",
      "government",
      "media",
      "financial",
      "transportation",
      "elections"
    ],
    motivation: "disruption / sabotage / espionage",
    activeSince: 2009,
    notableCampaigns: [
      "BlackEnergy Ukraine power grid (2015)",
      "Industroyer / CrashOverride (2016)",
      "NotPetya (2017)",
      "Olympic Destroyer (2018)",
      "Cyclops Blink (2022)",
      "Industroyer2 Ukraine (2022)",
      "WhisperGate-adjacent operations (2022-2023)"
    ]
  },

  // ---------------------------------------------------------------
  //  7  Turla
  // ---------------------------------------------------------------
  {
    name: "Turla",
    aliases: [
      "Snake",
      "VENOMOUS BEAR",
      "Secret Blizzard",
      "KRYPTON",
      "Waterbug",
      "Uroburos",
      "WhiteBear",
      "Pfinet",
      "TAG-0530"
    ],
    origin: "Russia",
    type: "nation-state",
    targets: [
      "government",
      "military",
      "diplomatic",
      "research",
      "education",
      "pharmaceutical"
    ],
    motivation: "espionage",
    activeSince: 1996,
    notableCampaigns: [
      "Agent.BTZ / Moonlight Maze (late 1990s)",
      "Epic Turla (2014)",
      "Satellite-based C2 hijacking (2015)",
      "Watering hole attacks on embassies (2017-2019)",
      "Snake malware infrastructure takedown (2023)",
      "Hijacking Pakistani APT infrastructure (2024)"
    ]
  },

  // ---------------------------------------------------------------
  //  8  Equation Group
  // ---------------------------------------------------------------
  {
    name: "Equation Group",
    aliases: [
      "EQGRP",
      "Tilded Team",
      "Lamberts"
    ],
    origin: "United States",
    type: "nation-state",
    targets: [
      "government",
      "military",
      "telecommunications",
      "aerospace",
      "energy",
      "nuclear research",
      "financial"
    ],
    motivation: "espionage / signals intelligence",
    activeSince: 1996,
    notableCampaigns: [
      "Stuxnet (jointly with Israel, 2010)",
      "Hard drive firmware implants (2001-2015)",
      "GRAYFISH, EQUATIONDRUG, DOUBLEFANTASY toolkits",
      "Shadow Brokers leak (2016-2017)",
      "EternalBlue / EternalRomance exploits"
    ]
  },

  // ---------------------------------------------------------------
  //  9  FIN7
  // ---------------------------------------------------------------
  {
    name: "FIN7",
    aliases: [
      "Carbanak",
      "Carbon Spider",
      "GOLD NIAGARA",
      "Navigator Group",
      "Sangria Tempest",
      "ELBRUS",
      "ITG14"
    ],
    origin: "Russia / Ukraine",
    type: "cybercriminal",
    targets: [
      "retail",
      "hospitality",
      "restaurants",
      "financial services",
      "point-of-sale systems"
    ],
    motivation: "financial gain",
    activeSince: 2013,
    notableCampaigns: [
      "Carbanak bank robbery campaign (2013-2018)",
      "Point-of-sale malware across US restaurant chains (2017)",
      "Combi Security fake pen-test company front (2018)",
      "Bastion Secure fake company for recruitment (2021)",
      "Black Basta ransomware affiliation (2022-2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 10  Gamaredon
  // ---------------------------------------------------------------
  {
    name: "Gamaredon",
    aliases: [
      "Primitive Bear",
      "ACTINIUM",
      "Aqua Blizzard",
      "Shuckworm",
      "Armageddon",
      "Winterflounder",
      "BlueAlpha",
      "UAC-0010"
    ],
    origin: "Russia",
    type: "nation-state",
    targets: [
      "Ukraine government",
      "Ukraine military",
      "Ukraine law enforcement",
      "Ukraine NGOs",
      "Ukraine defense sector"
    ],
    motivation: "espionage / disruption",
    activeSince: 2013,
    notableCampaigns: [
      "Persistent targeting of Ukrainian government (2014-present)",
      "Pteranodon / Pterodo backdoor campaigns",
      "GammaLoad / GammaSteel information stealers (2022-2024)",
      "USB propagating worm attacks (2023)",
      "Cloudflare tunneling for C2 evasion (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 11  Kimsuky
  // ---------------------------------------------------------------
  {
    name: "Kimsuky",
    aliases: [
      "Velvet Chollima",
      "THALLIUM",
      "Emerald Sleet",
      "Black Banshee",
      "Springtail",
      "TA406",
      "APT43",
      "ITG16"
    ],
    origin: "North Korea",
    type: "nation-state",
    targets: [
      "South Korea government",
      "think tanks",
      "nuclear policy",
      "academia",
      "defense",
      "media",
      "cryptocurrency"
    ],
    motivation: "espionage / intelligence collection",
    activeSince: 2012,
    notableCampaigns: [
      "KHNP nuclear reactor operator targeting (2014)",
      "Stolen Pencil academic targeting (2018)",
      "AppleSeed / BabyShark campaigns (2019-2022)",
      "Credential harvesting via fake login portals (2020-2024)",
      "ReconShark reconnaissance tool deployment (2023)",
      "Social engineering of NK policy experts (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 12  OceanLotus / APT32
  // ---------------------------------------------------------------
  {
    name: "APT32",
    aliases: [
      "OceanLotus",
      "Canvas Cyclone",
      "BISMUTH",
      "SeaLotus",
      "APT-C-00",
      "Cobalt Kitty"
    ],
    origin: "Vietnam",
    type: "nation-state",
    targets: [
      "government",
      "media",
      "human rights",
      "manufacturing",
      "technology",
      "hospitality",
      "automotive"
    ],
    motivation: "espionage / political surveillance",
    activeSince: 2012,
    notableCampaigns: [
      "Targeting of ASEAN-related entities (2017-2020)",
      "COVID-19 intelligence gathering (2020)",
      "Automotive industry espionage (2019)",
      "Supply-chain attacks via compromised software (2020)",
      "Watering hole attacks on Vietnamese diaspora media (2021)"
    ]
  },

  // ---------------------------------------------------------------
  // 13  MuddyWater
  // ---------------------------------------------------------------
  {
    name: "MuddyWater",
    aliases: [
      "MERCURY",
      "Mango Sandstorm",
      "Static Kitten",
      "Seedworm",
      "TEMP.Zagros",
      "TA450"
    ],
    origin: "Iran",
    type: "nation-state",
    targets: [
      "government",
      "telecommunications",
      "energy",
      "defense",
      "academia",
      "Middle East / South Asia / Europe"
    ],
    motivation: "espionage",
    activeSince: 2017,
    notableCampaigns: [
      "PowerShell-based POWERSTATS backdoor (2017-2019)",
      "Targeting of Middle Eastern telecommunications (2019)",
      "Israel and Turkey government intrusions (2020-2022)",
      "Exploitation of Atera, SimpleHelp RMM tools (2023)",
      "Phishing campaigns against Israeli targets (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 14  Charming Kitten / APT35
  // ---------------------------------------------------------------
  {
    name: "APT35",
    aliases: [
      "Charming Kitten",
      "PHOSPHORUS",
      "Mint Sandstorm",
      "NewsBeef",
      "Newscaster",
      "TA453",
      "Ajax Security Team",
      "ITG18"
    ],
    origin: "Iran",
    type: "nation-state",
    targets: [
      "academia",
      "government",
      "defense",
      "journalism",
      "human rights",
      "nuclear policy",
      "healthcare"
    ],
    motivation: "espionage / surveillance of dissidents",
    activeSince: 2011,
    notableCampaigns: [
      "HBO data breach (2017)",
      "Impersonation of Munich Security Conference (2020)",
      "SpoofedScholars credential harvesting (2021)",
      "Log4Shell exploitation (2022)",
      "Israel-Hamas conflict espionage (2023-2024)",
      "Targeting of presidential campaign staff (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 15  Volt Typhoon
  // ---------------------------------------------------------------
  {
    name: "Volt Typhoon",
    aliases: [
      "BRONZE SILHOUETTE",
      "Vanguard Panda",
      "DEV-0391",
      "Insidious Taurus",
      "UNC3236"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "critical infrastructure",
      "communications",
      "energy",
      "water",
      "transportation",
      "government",
      "maritime"
    ],
    motivation: "pre-positioning for disruption / espionage",
    activeSince: 2021,
    notableCampaigns: [
      "Living-off-the-land attacks on US critical infrastructure (2023)",
      "Compromise of US telecommunications providers (2023)",
      "Small office / home office router botnet (KV-Botnet) (2023)",
      "Guam and Pacific territory infrastructure targeting (2023)",
      "Water treatment and power grid pre-positioning (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 16  Salt Typhoon
  // ---------------------------------------------------------------
  {
    name: "Salt Typhoon",
    aliases: [
      "GhostEmperor",
      "FamousSparrow",
      "UNC2286",
      "Earth Estries"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "telecommunications",
      "ISPs",
      "government wiretap systems",
      "hotels",
      "government"
    ],
    motivation: "espionage / signals intelligence",
    activeSince: 2019,
    notableCampaigns: [
      "Compromise of major US ISPs (AT&T, Verizon, T-Mobile) (2024)",
      "Lawful intercept system infiltration (2024)",
      "Hotel guest espionage (FamousSparrow) (2021)",
      "Targeting of government officials' communications (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 17  Scattered Spider
  // ---------------------------------------------------------------
  {
    name: "Scattered Spider",
    aliases: [
      "UNC3944",
      "Octo Tempest",
      "0ktapus",
      "Scatter Swine",
      "Star Fraud",
      "Muddled Libra"
    ],
    origin: "United States / United Kingdom",
    type: "cybercriminal",
    targets: [
      "technology",
      "telecommunications",
      "hospitality",
      "gaming",
      "retail",
      "financial services",
      "BPO / outsourcing"
    ],
    motivation: "financial gain / extortion",
    activeSince: 2022,
    notableCampaigns: [
      "0ktapus phishing campaign targeting 130+ orgs (2022)",
      "Twilio and Cloudflare phishing (2022)",
      "MGM Resorts attack via social engineering (2023)",
      "Caesars Entertainment ransom ($15M) (2023)",
      "ALPHV/BlackCat ransomware affiliation (2023-2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 18  APT40 / Leviathan
  // ---------------------------------------------------------------
  {
    name: "APT40",
    aliases: [
      "Leviathan",
      "BRONZE MOHAWK",
      "Gingham Typhoon",
      "GADOLINIUM",
      "Kryptonite Panda",
      "TA423",
      "Red Ladon"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "maritime",
      "defense",
      "aviation",
      "technology",
      "education",
      "government",
      "South China Sea region"
    ],
    motivation: "espionage / naval intelligence",
    activeSince: 2009,
    notableCampaigns: [
      "South China Sea-related espionage (2013-2020)",
      "COVID-19 research targeting (2020)",
      "Australian government compromise (2022)",
      "Rapid exploitation of public-facing applications (2023)",
      "ScanBox framework watering holes (2022-2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 19  Hafnium
  // ---------------------------------------------------------------
  {
    name: "Hafnium",
    aliases: [
      "Silk Typhoon",
      "HAFNIUM",
      "Red Dev 13"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "defense",
      "higher education",
      "NGOs",
      "think tanks",
      "healthcare",
      "legal",
      "infectious disease researchers"
    ],
    motivation: "espionage / data exfiltration",
    activeSince: 2017,
    notableCampaigns: [
      "Microsoft Exchange Server ProxyLogon exploitation (2021)",
      "Targeting of US-based defense industrial base (2020-2021)",
      "COVID-19 policy research espionage (2020)",
      "Supply chain attacks via IT providers (2023)"
    ]
  },

  // ---------------------------------------------------------------
  // 20  DarkSide
  // ---------------------------------------------------------------
  {
    name: "DarkSide",
    aliases: [
      "Carbon Spider (partial overlap with FIN7)",
      "UNC2465"
    ],
    origin: "Russia",
    type: "cybercriminal",
    targets: [
      "critical infrastructure",
      "energy",
      "manufacturing",
      "legal",
      "insurance",
      "healthcare"
    ],
    motivation: "financial gain (ransomware-as-a-service)",
    activeSince: 2020,
    notableCampaigns: [
      "Colonial Pipeline ransomware attack (2021)",
      "Toshiba Tec Europe compromise (2021)",
      "Multiple RaaS affiliate campaigns (2020-2021)",
      "Rebranded as BlackMatter (2021)"
    ]
  },

  // ---------------------------------------------------------------
  // 21  REvil / Sodinokibi
  // ---------------------------------------------------------------
  {
    name: "REvil",
    aliases: [
      "Sodinokibi",
      "GOLD SOUTHFIELD",
      "Pinchy Spider"
    ],
    origin: "Russia",
    type: "cybercriminal",
    targets: [
      "managed service providers",
      "technology",
      "legal",
      "manufacturing",
      "agriculture",
      "retail"
    ],
    motivation: "financial gain (ransomware-as-a-service)",
    activeSince: 2019,
    notableCampaigns: [
      "Kaseya VSA supply chain attack (2021)",
      "JBS Foods ransom ($11M) (2021)",
      "Travelex attack (2020)",
      "Acer $50M ransom demand (2021)",
      "Apple supplier Quanta extortion (2021)"
    ]
  },

  // ---------------------------------------------------------------
  // 22  LockBit
  // ---------------------------------------------------------------
  {
    name: "LockBit",
    aliases: [
      "ABCD ransomware",
      "LockBit 2.0",
      "LockBit 3.0 / Black",
      "LockBit Green",
      "Bitwise Spider",
      "GOLD MYSTIC"
    ],
    origin: "Russia",
    type: "cybercriminal",
    targets: [
      "healthcare",
      "government",
      "financial",
      "manufacturing",
      "education",
      "legal",
      "technology"
    ],
    motivation: "financial gain (ransomware-as-a-service)",
    activeSince: 2019,
    notableCampaigns: [
      "Royal Mail UK disruption (2023)",
      "Boeing data exfiltration (2023)",
      "ICBC Financial Services (2023)",
      "Operation Cronos takedown (2024)",
      "Affiliate rebranding attempts post-takedown (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 23  Conti
  // ---------------------------------------------------------------
  {
    name: "Conti",
    aliases: [
      "Wizard Spider (partial)",
      "GOLD ULRICK",
      "DEV-0230"
    ],
    origin: "Russia",
    type: "cybercriminal",
    targets: [
      "healthcare",
      "government",
      "critical infrastructure",
      "education",
      "retail"
    ],
    motivation: "financial gain (ransomware-as-a-service)",
    activeSince: 2020,
    notableCampaigns: [
      "Ireland HSE health system attack (2021)",
      "Costa Rica government ($20M demand) (2022)",
      "Conti leaks / internal chat exposure (2022)",
      "Fragmentation into Royal, Black Basta, Karakurt (2022)"
    ]
  },

  // ---------------------------------------------------------------
  // 24  Wizard Spider / TrickBot
  // ---------------------------------------------------------------
  {
    name: "Wizard Spider",
    aliases: [
      "GOLD BLACKBURN",
      "TrickBot Group",
      "UNC1878",
      "DEV-0193",
      "Periwinkle Tempest"
    ],
    origin: "Russia",
    type: "cybercriminal",
    targets: [
      "financial services",
      "healthcare",
      "government",
      "technology",
      "education"
    ],
    motivation: "financial gain",
    activeSince: 2016,
    notableCampaigns: [
      "TrickBot banking trojan campaigns (2016-2022)",
      "Ryuk ransomware operations (2018-2021)",
      "BazarLoader / BazarBackdoor distribution (2020-2022)",
      "TrickBot infrastructure takedown (2020, 2022)",
      "Conti ransomware operations (2020-2022)"
    ]
  },

  // ---------------------------------------------------------------
  // 25  TA505
  // ---------------------------------------------------------------
  {
    name: "TA505",
    aliases: [
      "Hive0065",
      "Graceful Spider",
      "GOLD TAHOE",
      "SectorJ04",
      "CL0P Gang (partial)"
    ],
    origin: "Russia",
    type: "cybercriminal",
    targets: [
      "financial",
      "retail",
      "healthcare",
      "hospitality",
      "education",
      "government"
    ],
    motivation: "financial gain",
    activeSince: 2014,
    notableCampaigns: [
      "Dridex banking trojan distribution (2014-2020)",
      "Locky ransomware distribution (2016-2017)",
      "Cl0p ransomware operations (2019-present)",
      "MOVEit Transfer exploitation (2023)",
      "GoAnywhere MFT exploitation (2023)",
      "Accellion FTA exploitation (2021)"
    ]
  },

  // ---------------------------------------------------------------
  // 26  Mustang Panda
  // ---------------------------------------------------------------
  {
    name: "Mustang Panda",
    aliases: [
      "BRONZE PRESIDENT",
      "Stately Taurus",
      "RedDelta",
      "TA416",
      "TEMP.Hex",
      "Camaro Dragon",
      "Earth Preta",
      "LuminousMoth"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "government",
      "NGOs",
      "think tanks",
      "religious institutions",
      "telecommunications",
      "Southeast Asia / Europe"
    ],
    motivation: "espionage",
    activeSince: 2014,
    notableCampaigns: [
      "Myanmar and Mongolia government targeting (2018-2022)",
      "European diplomatic entity espionage (2022-2024)",
      "TP-Link router firmware implants (2023)",
      "PlugX USB worm propagation (2023)",
      "Taiwan / Philippines military intelligence (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 27  APT10 / Stone Panda
  // ---------------------------------------------------------------
  {
    name: "APT10",
    aliases: [
      "Stone Panda",
      "MenuPass",
      "CVNX",
      "POTASSIUM",
      "Red Apollo",
      "Cicada",
      "BRONZE RIVERSIDE"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "managed service providers",
      "technology",
      "aerospace",
      "government",
      "healthcare",
      "manufacturing",
      "Japan"
    ],
    motivation: "espionage / intellectual property theft",
    activeSince: 2006,
    notableCampaigns: [
      "Operation Cloud Hopper MSP compromise (2016-2018)",
      "Japanese media and government targeting (2017-2020)",
      "LODEINFO malware campaigns (2019-2023)",
      "Cicada reemergence post-indictment (2021)"
    ]
  },

  // ---------------------------------------------------------------
  // 28  APT33 / Elfin
  // ---------------------------------------------------------------
  {
    name: "APT33",
    aliases: [
      "Elfin",
      "HOLMIUM",
      "Peach Sandstorm",
      "Magnallium",
      "Refined Kitten",
      "COBALT TRINITY"
    ],
    origin: "Iran",
    type: "nation-state",
    targets: [
      "aviation",
      "energy",
      "petrochemical",
      "defense",
      "manufacturing",
      "government"
    ],
    motivation: "espionage / destructive attacks",
    activeSince: 2013,
    notableCampaigns: [
      "Shamoon wiper deployment attribution (2016-2017)",
      "US and Saudi Arabian aviation targeting (2017-2019)",
      "Password spraying against defense contractors (2023)",
      "Tickler backdoor against satellite and defense (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 29  OilRig / APT34
  // ---------------------------------------------------------------
  {
    name: "APT34",
    aliases: [
      "OilRig",
      "Helix Kitten",
      "HAZEL SANDSTORM",
      "Chrysene",
      "EUROPIUM",
      "Crambus",
      "Cobalt Gypsy",
      "ITG13"
    ],
    origin: "Iran",
    type: "nation-state",
    targets: [
      "financial",
      "government",
      "energy",
      "chemical",
      "telecommunications",
      "Middle East"
    ],
    motivation: "espionage",
    activeSince: 2014,
    notableCampaigns: [
      "DNS hijacking across Middle East (2018-2019)",
      "OilRig tools leak on Telegram (2019)",
      "SIESTAGRAPH / Menorah backdoor (2023)",
      "Targeting of Middle Eastern government via Exchange (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 30  Ember Bear
  // ---------------------------------------------------------------
  {
    name: "Ember Bear",
    aliases: [
      "UNC2589",
      "Cadet Blizzard",
      "DEV-0586",
      "FROZENVISTA",
      "Bleeding Bear"
    ],
    origin: "Russia",
    type: "nation-state",
    targets: [
      "Ukraine government",
      "NATO countries",
      "IT sector",
      "government services"
    ],
    motivation: "disruption / espionage",
    activeSince: 2021,
    notableCampaigns: [
      "WhisperGate destructive wiper (January 2022)",
      "Defacement of Ukrainian government websites (2022)",
      "Targeting of NATO-aligned nations (2022-2023)",
      "Exploitation of Confluence and Exchange servers (2023)"
    ]
  },

  // ---------------------------------------------------------------
  // 31  Winnti / APT17
  // ---------------------------------------------------------------
  {
    name: "APT17",
    aliases: [
      "Winnti Group (original)",
      "AURORA PANDA",
      "Tailgater Team",
      "Dogfish",
      "Deputy Dog",
      "Axiom"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "gaming industry",
      "technology",
      "defense",
      "government",
      "chemical"
    ],
    motivation: "espionage / financial gain",
    activeSince: 2010,
    notableCampaigns: [
      "Operation Aurora (2009-2010)",
      "TechNet forum C2 abuse (2015)",
      "Targeting of Asian gaming companies (2011-2019)",
      "IT supply chain intrusions (2020)"
    ]
  },

  // ---------------------------------------------------------------
  // 32  Dragonfly / Energetic Bear
  // ---------------------------------------------------------------
  {
    name: "Dragonfly",
    aliases: [
      "Energetic Bear",
      "IRON LIBERTY",
      "Crouching Yeti",
      "DYMALLOY",
      "Berserk Bear",
      "BROMINE",
      "TG-4192"
    ],
    origin: "Russia",
    type: "nation-state",
    targets: [
      "energy",
      "industrial control systems",
      "nuclear",
      "aviation",
      "government",
      "water / utilities"
    ],
    motivation: "espionage / pre-positioning for sabotage",
    activeSince: 2010,
    notableCampaigns: [
      "Dragonfly 1.0 ICS reconnaissance (2011-2014)",
      "Dragonfly 2.0 US/EU energy grid (2015-2017)",
      "Trojanized ICS vendor software (2013-2014)",
      "San Francisco International Airport watering hole (2020)"
    ]
  },

  // ---------------------------------------------------------------
  // 33  BlackTech
  // ---------------------------------------------------------------
  {
    name: "BlackTech",
    aliases: [
      "Palmerworm",
      "CIRCUIT PANDA",
      "Manga Taurus",
      "Red Djinn",
      "TEMP.Overboard"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "technology",
      "media",
      "telecommunications",
      "electronics",
      "government",
      "defense",
      "Japan / Taiwan"
    ],
    motivation: "espionage",
    activeSince: 2010,
    notableCampaigns: [
      "Router firmware modification for stealth (2023)",
      "Targeting of Taiwanese and Japanese defense (2019-2023)",
      "PLEAD / TSCookie campaigns (2018-2021)",
      "Flagpro malware against Japan (2022)"
    ]
  },

  // ---------------------------------------------------------------
  // 34  Evilnum / DeathStalker
  // ---------------------------------------------------------------
  {
    name: "DeathStalker",
    aliases: [
      "Evilnum",
      "Janicab",
      "Powersing"
    ],
    origin: "Unknown (suspected mercenary)",
    type: "cyber mercenary",
    targets: [
      "financial",
      "fintech",
      "legal",
      "forex / cryptocurrency",
      "travel agencies"
    ],
    motivation: "espionage-for-hire / financial intelligence",
    activeSince: 2012,
    notableCampaigns: [
      "Evilnum JavaScript trojan campaigns (2018-2020)",
      "Dead Drop Resolvers using social media (2020)",
      "Janicab macOS and Windows targeting (2015-2022)",
      "VileRAT campaigns against forex entities (2023)"
    ]
  },

  // ---------------------------------------------------------------
  // 35  Patchwork / Dropping Elephant
  // ---------------------------------------------------------------
  {
    name: "Patchwork",
    aliases: [
      "Dropping Elephant",
      "Chinastrats",
      "MONSOON",
      "Zinc Emery",
      "Quilted Tiger",
      "APT-C-09"
    ],
    origin: "India",
    type: "nation-state",
    targets: [
      "Pakistan government",
      "China",
      "Bangladesh",
      "diplomatic entities",
      "think tanks",
      "defense"
    ],
    motivation: "espionage",
    activeSince: 2009,
    notableCampaigns: [
      "Copy-paste operations reusing public exploits (2015-2020)",
      "BADNEWS backdoor campaigns (2016-2021)",
      "Self-infection leading to tool disclosure (2022)",
      "Ragnatela RAT deployment (2022)"
    ]
  },

  // ---------------------------------------------------------------
  // 36  SideWinder / Rattlesnake
  // ---------------------------------------------------------------
  {
    name: "SideWinder",
    aliases: [
      "Rattlesnake",
      "T-APT-04",
      "APT-C-17",
      "Hardcore Nationalist",
      "Baby Elephant"
    ],
    origin: "India",
    type: "nation-state",
    targets: [
      "Pakistan military",
      "China",
      "Nepal",
      "Sri Lanka",
      "Bangladesh",
      "government",
      "defense"
    ],
    motivation: "espionage",
    activeSince: 2012,
    notableCampaigns: [
      "Persistent targeting of Pakistani military (2016-present)",
      "South Asian government phishing (2019-2022)",
      "Android spyware deployment (2020-2021)",
      "Server-side polymorphism for evasion (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 37  Ghostwriter / UNC1151
  // ---------------------------------------------------------------
  {
    name: "Ghostwriter",
    aliases: [
      "UNC1151",
      "Storm-0257"
    ],
    origin: "Belarus",
    type: "nation-state",
    targets: [
      "Lithuania",
      "Latvia",
      "Poland",
      "Ukraine",
      "NATO countries",
      "media",
      "government"
    ],
    motivation: "information operations / espionage",
    activeSince: 2016,
    notableCampaigns: [
      "Anti-NATO disinformation campaigns (2017-2022)",
      "Compromised news sites to plant fake stories (2020)",
      "Credential phishing of Polish officials (2021)",
      "Belarus-aligned influence operations during Russia-Ukraine war (2022-2023)"
    ]
  },

  // ---------------------------------------------------------------
  // 38  Agrius
  // ---------------------------------------------------------------
  {
    name: "Agrius",
    aliases: [
      "DEV-0227",
      "Pink Sandstorm",
      "BlackShadow",
      "Americium"
    ],
    origin: "Iran",
    type: "nation-state",
    targets: [
      "Israel",
      "South Africa",
      "diamond industry",
      "technology",
      "insurance",
      "education"
    ],
    motivation: "destructive / espionage / hack-and-leak",
    activeSince: 2020,
    notableCampaigns: [
      "Fantasy wiper against Israeli targets (2021-2022)",
      "Apostle ransomware disguised as wiper (2021)",
      "Cyberserv hosting compromise (2021)",
      "South African diamond industry attacks (2022)",
      "Moneybird ransomware deployment (2023)"
    ]
  },

  // ---------------------------------------------------------------
  // 39  LAPSUS$
  // ---------------------------------------------------------------
  {
    name: "LAPSUS$",
    aliases: [
      "DEV-0537",
      "Strawberry Tempest"
    ],
    origin: "United Kingdom / Brazil",
    type: "cybercriminal / hacktivist",
    targets: [
      "technology",
      "gaming",
      "telecommunications",
      "government",
      "healthcare",
      "retail"
    ],
    motivation: "notoriety / financial gain / extortion",
    activeSince: 2021,
    notableCampaigns: [
      "NVIDIA source code theft (2022)",
      "Samsung source code leak (2022)",
      "Microsoft Azure DevOps compromise (2022)",
      "Okta third-party breach (2022)",
      "Uber internal systems compromise (2022)",
      "Rockstar Games GTA VI leak (2022)"
    ]
  },

  // ---------------------------------------------------------------
  // 40  ChamelGang
  // ---------------------------------------------------------------
  {
    name: "ChamelGang",
    aliases: [
      "CamoFei"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "aviation",
      "government",
      "energy",
      "India",
      "Russia (incidentally)",
      "Taiwan",
      "Japan"
    ],
    motivation: "espionage",
    activeSince: 2021,
    notableCampaigns: [
      "DoorMe backdoor against aviation (2021)",
      "BeaconLoader and CatB ransomware as cover (2022)",
      "AIIMS India healthcare intrusion (2022)",
      "Disguising espionage as ransomware (2023-2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 41  Earth Lusca
  // ---------------------------------------------------------------
  {
    name: "Earth Lusca",
    aliases: [
      "TAG-22",
      "Charcoal Typhoon",
      "CHROMIUM",
      "ControlX"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "government",
      "education",
      "media",
      "gambling",
      "COVID-19 research",
      "religious organizations",
      "democracy movements"
    ],
    motivation: "espionage / financial gain",
    activeSince: 2019,
    notableCampaigns: [
      "Exploitation of ProxyShell, Log4Shell (2021-2022)",
      "Cobalt Strike and ShadowPad deployment (2022)",
      "Targeting of Asian government agencies (2023)",
      "SprySOCKS Linux backdoor (2023)"
    ]
  },

  // ---------------------------------------------------------------
  // 42  Flax Typhoon
  // ---------------------------------------------------------------
  {
    name: "Flax Typhoon",
    aliases: [
      "Ethereal Panda",
      "Storm-0919",
      "RedJuliett"
    ],
    origin: "China",
    type: "nation-state",
    targets: [
      "Taiwan government agencies",
      "education",
      "critical manufacturing",
      "IT organizations",
      "IoT devices worldwide"
    ],
    motivation: "espionage / pre-positioning",
    activeSince: 2021,
    notableCampaigns: [
      "Living-off-the-land persistence in Taiwan (2022-2023)",
      "Raptor Train IoT botnet (260K+ devices) (2024)",
      "SOHO router exploitation for proxy networks (2024)",
      "Targeting of Taiwanese defense entities (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 43  Storm-0558
  // ---------------------------------------------------------------
  {
    name: "Storm-0558",
    aliases: [],
    origin: "China",
    type: "nation-state",
    targets: [
      "government email systems",
      "diplomatic entities",
      "US government agencies",
      "European government"
    ],
    motivation: "espionage",
    activeSince: 2021,
    notableCampaigns: [
      "Microsoft cloud email breach via forged tokens (2023)",
      "Compromise of US State and Commerce Dept emails (2023)",
      "Acquisition of Microsoft signing key (2023)"
    ]
  },

  // ---------------------------------------------------------------
  // 44  Star Blizzard (Callisto)
  // ---------------------------------------------------------------
  {
    name: "Star Blizzard",
    aliases: [
      "Callisto Group",
      "COLDRIVER",
      "SEABORGIUM",
      "TA446",
      "BlueCharlie"
    ],
    origin: "Russia",
    type: "nation-state",
    targets: [
      "academia",
      "defense",
      "government",
      "NGOs",
      "think tanks",
      "journalists"
    ],
    motivation: "espionage / credential harvesting",
    activeSince: 2015,
    notableCampaigns: [
      "UK government official phishing (2022)",
      "Nuclear research lab targeting (2023)",
      "Evasion to Proton Mail and EvilGinx (2023)",
      "DOJ domain seizure operation (2024)"
    ]
  },

  // ---------------------------------------------------------------
  // 45  ALPHV / BlackCat
  // ---------------------------------------------------------------
  {
    name: "ALPHV",
    aliases: [
      "BlackCat",
      "Noberus",
      "GOLD BLAZER"
    ],
    origin: "Russia",
    type: "cybercriminal",
    targets: [
      "healthcare",
      "financial",
      "government",
      "education",
      "energy",
      "legal",
      "technology"
    ],
    motivation: "financial gain (ransomware-as-a-service)",
    activeSince: 2021,
    notableCampaigns: [
      "First Rust-based RaaS platform (2021)",
      "Swissport aviation services attack (2022)",
      "Reddit data breach (2023)",
      "Change Healthcare attack ($22M ransom) (2024)",
      "MGM Resorts (via Scattered Spider affiliate) (2023)",
      "FBI seizure and re-seizure of leak site (2023)"
    ]
  }
];


// ===================================================================
//  2. MALWARE FAMILIES  (40+)
//  Each entry: { name, type, description, iocs, detection }
// ===================================================================

const MALWARE_FAMILIES = [
  // ---------------------------------------------------------------
  //  1  Cobalt Strike
  // ---------------------------------------------------------------
  {
    name: "Cobalt Strike",
    type: "command-and-control framework / post-exploitation",
    description:
      "Commercial adversary simulation tool heavily abused by threat actors. " +
      "Provides beacon payloads for C2, lateral movement, credential harvesting, " +
      "and payload delivery. Cracked copies are ubiquitous in intrusions.",
    iocs: [
      "Default SSL certificate serial 146473198",
      "Named pipes: \\\\MSSE-*-server, \\\\postex_*",
      "Default User-Agent strings from malleable profiles",
      "Beacon watermark values",
      "Default staging URIs: /vcs, /ptj, /activity",
      "Default port 50050 for Team Server",
      "Process injection into rundll32.exe or dllhost.exe"
    ],
    detection: [
      "YARA rules for beacon shellcode stager",
      "JA3/JA3S fingerprints for default HTTPS profile",
      "Sysmon Event ID 17/18 for named pipe creation",
      "Memory scanning for reflective DLL loader patterns",
      "Network signatures for default malleable C2 profiles"
    ]
  },

  // ---------------------------------------------------------------
  //  2  Mimikatz
  // ---------------------------------------------------------------
  {
    name: "Mimikatz",
    type: "credential theft",
    description:
      "Open-source tool for extracting credentials from Windows memory. " +
      "Can dump plaintext passwords, NTLM hashes, Kerberos tickets, and " +
      "perform pass-the-hash, pass-the-ticket, and Golden Ticket attacks.",
    iocs: [
      "Process accessing lsass.exe memory",
      "Strings: mimikatz, gentilkiwi, sekurlsa",
      "LSASS memory dumps via comsvcs.dll MiniDump",
      "File names: mimi.exe, mimi32.exe, mimi64.exe, m.exe",
      "Registry key reads from SAM and SECURITY hives"
    ],
    detection: [
      "Sysmon Event ID 10 (process access to lsass.exe)",
      "Windows Event 4624 type 9 (NewCredentials logon)",
      "Windows Event 4672 (special privileges assigned)",
      "Credential Guard alerts",
      "YARA rules for sekurlsa module strings"
    ]
  },

  // ---------------------------------------------------------------
  //  3  Emotet
  // ---------------------------------------------------------------
  {
    name: "Emotet",
    type: "loader / botnet / banking trojan",
    description:
      "Originally a banking trojan that evolved into a major malware-as-a-service " +
      "loader and botnet. Spreads via malicious email attachments (macro-enabled " +
      "documents) and delivers secondary payloads including TrickBot, QBot, and " +
      "various ransomware families.",
    iocs: [
      "Macro-enabled Office documents with obfuscated VBA",
      "PowerShell download cradles with multiple fallback URLs",
      "Persistence via Windows services or scheduled tasks",
      "C2 communication on non-standard ports",
      "Distinctive binary packing and unpacking stubs",
      "Module DLLs loaded via regsvr32.exe or rundll32.exe"
    ],
    detection: [
      "Sigma rules for Emotet process chains",
      "Network signatures for Emotet C2 protocol",
      "Behavioral detection of document macro execution chains",
      "YARA rules for Emotet packer and loader stages",
      "Email gateway rules for characteristic lure patterns"
    ]
  },

  // ---------------------------------------------------------------
  //  4  QakBot / QBot
  // ---------------------------------------------------------------
  {
    name: "QakBot",
    type: "banking trojan / loader",
    description:
      "Long-running banking trojan and initial access broker. Harvests " +
      "credentials, deploys additional payloads, and facilitates ransomware. " +
      "Taken down by FBI Operation Duck Hunt in 2023 but partially resurfaced.",
    iocs: [
      "DLL side-loading via legitimate executables (calc.exe, explorer.exe)",
      "HTML smuggling email attachments",
      "ISO/IMG/OneNote delivery files",
      "Registry Run key persistence",
      "Web inject configurations for banking sites",
      "Distinctive C2 protocol with RC4 encryption"
    ],
    detection: [
      "Process tree: email client -> archive -> script -> regsvr32/rundll32",
      "Sysmon Event ID 1 for regsvr32 loading DLLs from temp directories",
      "Network detection for QakBot C2 beacon patterns",
      "YARA rules for QakBot stager and core module",
      "Abnormal scheduled task creation with random names"
    ]
  },

  // ---------------------------------------------------------------
  //  5  TrickBot
  // ---------------------------------------------------------------
  {
    name: "TrickBot",
    type: "banking trojan / modular malware",
    description:
      "Modular banking trojan and botnet that evolved from the Dyre trojan. " +
      "Features web injection, credential theft, network reconnaissance, and " +
      "lateral movement modules. Major delivery vehicle for Ryuk and Conti ransomware.",
    iocs: [
      "Scheduled tasks with names like 'MsSystemWatcher'",
      "Modules: injectDll, mailsearcher, networkDll, psfin, shareDll, tabDll",
      "C2 communication using HTTPS with distinctive URI patterns",
      "EternalBlue / EternalRomance lateral movement",
      "Group tags (gtag) in configuration files",
      "DLL loaded via rundll32 with specific exports"
    ],
    detection: [
      "Sigma rules for TrickBot scheduled task patterns",
      "Network signatures for TrickBot C2 protocol",
      "Behavioral detection of web injection hooks",
      "YARA rules for TrickBot modules and packer",
      "Sysmon monitoring for characteristic process chains"
    ]
  },

  // ---------------------------------------------------------------
  //  6  ShadowPad
  // ---------------------------------------------------------------
  {
    name: "ShadowPad",
    type: "modular backdoor / RAT",
    description:
      "Modular backdoor platform shared among multiple Chinese APT groups. " +
      "Evolved from the Winnti/PlugX lineage. Features a plugin architecture " +
      "supporting keylogging, screen capture, file theft, and C2 communication " +
      "via multiple protocols.",
    iocs: [
      "DLL side-loading chains using legitimate signed executables",
      "Encrypted payloads stored in registry or files",
      "DNS-based C2 with encoded subdomains",
      "Distinctive in-memory shellcode decryption routines",
      "Module registry: keylogger, screen, file, process, network modules"
    ],
    detection: [
      "YARA rules for ShadowPad shellcode loader",
      "Sysmon Event ID 7 for DLL side-loading patterns",
      "DNS query anomaly detection for encoded hostnames",
      "Memory forensics for characteristic decryption stubs",
      "Behavioral analysis of legitimate process loading unsigned DLLs"
    ]
  },

  // ---------------------------------------------------------------
  //  7  PlugX
  // ---------------------------------------------------------------
  {
    name: "PlugX",
    type: "RAT / backdoor",
    description:
      "Long-running remote access trojan associated with Chinese espionage " +
      "groups. Uses DLL side-loading for execution and features modular plugin " +
      "architecture. Recent variants include USB worm propagation capability.",
    iocs: [
      "DLL side-loading triad: legitimate EXE + malicious DLL + encrypted payload",
      "Mutex patterns: Global\\PlugXMutex, RhinoX, USB_NOTIFY",
      "Registry persistence in Run/RunOnce keys",
      "C2 traffic disguised as HTTP with custom headers",
      "USB propagation via shortcut (LNK) files on removable drives"
    ],
    detection: [
      "YARA rules for PlugX loader and payload decryption",
      "Sysmon monitoring for known side-loading binaries",
      "Network detection for PlugX C2 protocol patterns",
      "USB monitoring for suspicious LNK file creation",
      "Behavioral detection of DLL search-order hijacking"
    ]
  },

  // ---------------------------------------------------------------
  //  8  Stuxnet
  // ---------------------------------------------------------------
  {
    name: "Stuxnet",
    type: "worm / ICS sabotage",
    description:
      "Highly sophisticated worm targeting Siemens STEP 7 SCADA systems, " +
      "specifically designed to sabotage Iranian nuclear centrifuges. Used " +
      "four zero-day exploits and stolen Realtek/JMicron code signing certificates. " +
      "Considered the first known cyberweapon targeting physical infrastructure.",
    iocs: [
      "Exploitation of CVE-2010-2568 (LNK), CVE-2010-2729 (print spooler)",
      "Files signed with stolen Realtek or JMicron certificates",
      "WinCC SQL Server default credential exploitation",
      "Siemens S7-300 PLC code injection (OB1/OB35 blocks)",
      "Peer-to-peer update mechanism via RPC"
    ],
    detection: [
      "Signatures for Stuxnet driver and DLL components",
      "Monitoring for unauthorized modifications to PLC code",
      "Network detection for Stuxnet P2P protocol",
      "File system monitoring for mrxnet.sys (rootkit driver)",
      "Anomalous Siemens STEP 7 project modifications"
    ]
  },

  // ---------------------------------------------------------------
  //  9  NotPetya
  // ---------------------------------------------------------------
  {
    name: "NotPetya",
    type: "destructive wiper (disguised as ransomware)",
    description:
      "Destructive wiper malware masquerading as Petya ransomware. Spread " +
      "via the compromised M.E.Doc Ukrainian tax software and used EternalBlue " +
      "and EternalRomance exploits. Caused an estimated $10B in global damage.",
    iocs: [
      "M.E.Doc software update mechanism as initial vector",
      "Use of EternalBlue (MS17-010) and EternalRomance",
      "Mimikatz-like credential harvester component",
      "MBR and MFT encryption with non-recoverable key",
      "WMIC and PsExec lateral movement",
      "Perfc.dll and perfc.dat payload files"
    ],
    detection: [
      "File hash signatures for known NotPetya components",
      "Network detection for EternalBlue exploitation attempts",
      "Behavioral detection of MBR modification",
      "Monitoring for mass lateral movement via WMIC/PsExec",
      "M.E.Doc update server integrity monitoring"
    ]
  },

  // ---------------------------------------------------------------
  // 10  WannaCry
  // ---------------------------------------------------------------
  {
    name: "WannaCry",
    type: "ransomware / worm",
    description:
      "Self-propagating ransomware worm that exploited the EternalBlue SMB " +
      "vulnerability (MS17-010). Infected over 300,000 systems in 150+ countries. " +
      "Attributed to the Lazarus Group. Featured a kill switch domain that was " +
      "accidentally discovered and activated.",
    iocs: [
      "Kill switch domain: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com",
      "File extension .WNCRY for encrypted files",
      "Tor C2 communication for payment",
      "SMB exploitation on port 445",
      "Bitcoin wallet addresses: 13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94 and others",
      "@WanaDecryptor@.exe dropper"
    ],
    detection: [
      "Network signatures for EternalBlue exploitation",
      "YARA rules for WannaCry binary and encrypted payload",
      "File system monitoring for .WNCRY extension changes",
      "Kill switch domain DNS resolution monitoring",
      "SMB traffic anomaly detection on port 445"
    ]
  },

  // ---------------------------------------------------------------
  // 11  Ryuk
  // ---------------------------------------------------------------
  {
    name: "Ryuk",
    type: "ransomware",
    description:
      "Targeted ransomware operated by Wizard Spider, typically deployed as " +
      "final payload after TrickBot or BazarLoader initial access. Known for " +
      "targeting large enterprises and demanding multi-million dollar ransoms. " +
      "Predecessor to Conti ransomware.",
    iocs: [
      "RyukReadMe.html or RyukReadMe.txt ransom notes",
      ".RYK extension appended to encrypted files",
      "Process injection into legitimate Windows processes",
      "Selective file encryption (skips Windows, System32, etc.)",
      "Persistence via registry Run keys",
      "Wake-on-LAN packets to power on sleeping machines"
    ],
    detection: [
      "YARA rules for Ryuk payload and dropper",
      "Behavioral detection of mass file encryption",
      "Monitoring for Wake-on-LAN broadcast packets",
      "Process injection detection via ETW or Sysmon",
      "Anomalous file extension modification patterns"
    ]
  },

  // ---------------------------------------------------------------
  // 12  BlackEnergy
  // ---------------------------------------------------------------
  {
    name: "BlackEnergy",
    type: "modular backdoor / ICS toolkit",
    description:
      "Modular malware initially a DDoS tool that evolved into a sophisticated " +
      "backdoor used by Sandworm against ICS/SCADA systems. BlackEnergy 3 was " +
      "used in the 2015 Ukraine power grid attack that caused widespread outages.",
    iocs: [
      "Macro-enabled Excel/Word documents as droppers",
      "Plugin architecture: ps (password stealer), vs (screenshot), fs (file system)",
      "C2 communication via HTTP POST with encrypted data",
      "KillDisk component for destructive attacks",
      "Targeting of OPC (OLE for Process Control) servers"
    ],
    detection: [
      "YARA rules for BlackEnergy plugins and dropper",
      "OPC server access anomaly monitoring",
      "Network detection for BlackEnergy C2 protocol",
      "ICS network traffic baseline deviation",
      "File system monitoring for KillDisk indicators"
    ]
  },

  // ---------------------------------------------------------------
  // 13  Industroyer / CrashOverride
  // ---------------------------------------------------------------
  {
    name: "Industroyer",
    type: "ICS attack framework",
    description:
      "Sophisticated malware framework specifically designed to attack " +
      "electric power grids. Features modules for four ICS protocols: " +
      "IEC 60870-5-101, IEC 60870-5-104, IEC 61850, and OPC DA. " +
      "Used in the December 2016 Ukraine power grid attack.",
    iocs: [
      "IEC 104 protocol communication from non-ICS workstations",
      "Abnormal OPC DA requests from unexpected sources",
      "Data wiper component targeting specific file extensions",
      "Backdoor component with configurable C2",
      "Scheduled tasks for coordinated payload execution"
    ],
    detection: [
      "ICS protocol anomaly detection (IEC 104, IEC 61850, OPC DA)",
      "Network monitoring for unauthorized SCADA protocol usage",
      "YARA rules for Industroyer components",
      "Behavioral detection of coordinated relay trip commands",
      "File system integrity monitoring on ICS workstations"
    ]
  },

  // ---------------------------------------------------------------
  // 14  SUNBURST (SolarWinds)
  // ---------------------------------------------------------------
  {
    name: "SUNBURST",
    type: "supply chain backdoor",
    description:
      "Supply chain backdoor injected into SolarWinds Orion software updates. " +
      "Distributed to approximately 18,000 organizations. Featured sophisticated " +
      "anti-detection including dormancy period, environmental checks, and C2 " +
      "communication disguised as legitimate Orion traffic.",
    iocs: [
      "Modified SolarWinds.Orion.Core.BusinessLayer.dll",
      "DGA domain pattern: avsvmcloud[.]com subdomains",
      "DNS CNAME records as C2 channel",
      "Delayed execution (12-14 day dormancy period)",
      "Process blocklist checking for security tools",
      "TEARDROP and RAINDROP secondary payloads"
    ],
    detection: [
      "Hash verification of Orion DLL files",
      "DNS monitoring for avsvmcloud[.]com patterns",
      "Network detection for anomalous Orion API traffic",
      "YARA rules for SUNBURST backdoor code",
      "Behavioral analysis of Orion process network connections"
    ]
  },

  // ---------------------------------------------------------------
  // 15  Agent Tesla
  // ---------------------------------------------------------------
  {
    name: "Agent Tesla",
    type: "information stealer / keylogger / RAT",
    description:
      "Widely-used .NET-based information stealer sold as malware-as-a-service. " +
      "Features keylogging, clipboard monitoring, screen capture, credential " +
      "theft from browsers, email clients, FTP clients, and VPNs. Exfiltrates " +
      "data via SMTP, FTP, Telegram, or HTTP.",
    iocs: [
      ".NET executable with heavy obfuscation",
      "SMTP exfiltration to attacker-controlled email",
      "Telegram Bot API calls for data exfiltration",
      "Persistence via Registry Run key or Startup folder",
      "Scheduled task or WMI subscription for persistence",
      "Anti-analysis: checking for VM, sandbox, debugger"
    ],
    detection: [
      "YARA rules for Agent Tesla obfuscation patterns",
      "Network monitoring for SMTP traffic from non-email processes",
      "Sysmon Event ID 1 for .NET process with suspicious flags",
      "Behavioral detection of keylogger API calls (SetWindowsHookEx)",
      "Telegram Bot API endpoint monitoring"
    ]
  },

  // ---------------------------------------------------------------
  // 16  Remcos RAT
  // ---------------------------------------------------------------
  {
    name: "Remcos RAT",
    type: "remote access trojan",
    description:
      "Commercial remote administration tool frequently abused by threat actors. " +
      "Features include keylogging, screen capture, webcam and microphone recording, " +
      "file management, and reverse proxy. Delivered via phishing emails with " +
      "malicious attachments.",
    iocs: [
      "Mutex patterns: Remcos_Mutex_*, Remcos-*",
      "Registry persistence: HKCU\\Software\\Remcos-*",
      "C2 communication on port 2404, 8080, or custom ports",
      "Configuration stored in PE resource section (encrypted RC4)",
      "Process hollowing into legitimate processes",
      "Keylog file stored in %AppData%\\remcos\\logs.dat"
    ],
    detection: [
      "YARA rules for Remcos PE structure and strings",
      "Sysmon Event ID 1 for process hollowing indicators",
      "Network monitoring for Remcos C2 protocol signature",
      "File system monitoring for remcos directory creation",
      "Registry monitoring for Remcos-prefixed keys"
    ]
  },

  // ---------------------------------------------------------------
  // 17  AsyncRAT
  // ---------------------------------------------------------------
  {
    name: "AsyncRAT",
    type: "remote access trojan",
    description:
      "Open-source .NET remote access trojan with modular plugin support. " +
      "Features include remote desktop, file management, keylogging, and " +
      "cryptocurrency mining plugin. Commonly delivered via phishing and " +
      "malicious scripts.",
    iocs: [
      "Mutex: AsyncMutex_* or custom configured mutex",
      ".NET binary with characteristic class names (Client, Settings, Algorithm)",
      "Persistence via scheduled tasks or Registry Run keys",
      "C2 communication via TCP with custom encryption",
      "Anti-analysis checks for virtual machines and sandboxes",
      "Pastebin/GitHub raw content as dead drop resolver for C2"
    ],
    detection: [
      "YARA rules for AsyncRAT .NET classes and methods",
      "Sysmon Event ID 1 for .NET process loading patterns",
      "Network monitoring for AsyncRAT handshake sequence",
      "Behavioral detection of screen capture API calls",
      "DNS/HTTP monitoring for dead drop resolver queries"
    ]
  },

  // ---------------------------------------------------------------
  // 18  Raccoon Stealer
  // ---------------------------------------------------------------
  {
    name: "Raccoon Stealer",
    type: "information stealer",
    description:
      "Malware-as-a-service information stealer that extracts credentials, " +
      "cookies, autofill data, and cryptocurrency wallets from infected systems. " +
      "Version 2.0 (RecordBreaker) rewritten in C/C++ for improved performance. " +
      "Operator arrested in 2022 but the malware continued via affiliates.",
    iocs: [
      "Distinctive C2 URL patterns with /aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2vK/",
      "Exfiltration of browser SQLite databases (Login Data, Cookies)",
      "Telegram channels used for C2 configuration",
      "Targeted cryptocurrency wallet extensions",
      "System fingerprinting data sent as initial beacon",
      "DLL dependencies loaded from C2 (sqlite3.dll, nss3.dll)"
    ],
    detection: [
      "YARA rules for Raccoon v2 payload structure",
      "File system monitoring for SQLite database copies in temp directories",
      "Network monitoring for Raccoon C2 URI patterns",
      "Behavioral detection of browser data file access by non-browser process",
      "Telegram API endpoint monitoring"
    ]
  },

  // ---------------------------------------------------------------
  // 19  RedLine Stealer
  // ---------------------------------------------------------------
  {
    name: "RedLine Stealer",
    type: "information stealer",
    description:
      "Widely-deployed .NET information stealer sold on underground forums. " +
      "Harvests credentials, cookies, cryptocurrency wallets, credit card data, " +
      "system information, and installed software. Often distributed via fake " +
      "software downloads, YouTube descriptions, and cracked software.",
    iocs: [
      ".NET executable with string encryption",
      "WCF (Windows Communication Foundation) protocol for C2",
      "Targeting of Chrome, Firefox, Opera, Edge stored credentials",
      "Cryptocurrency wallet scanning (Metamask, Phantom, etc.)",
      "System info collection: hardware ID, OS, installed software",
      "Persistence usually absent (smash-and-grab approach)"
    ],
    detection: [
      "YARA rules for RedLine .NET structure",
      "Network monitoring for WCF SOAP protocol from unusual processes",
      "Behavioral detection of mass browser data file access",
      "File system monitoring for credential database copying",
      "Process monitoring for rapid system enumeration commands"
    ]
  },

  // ---------------------------------------------------------------
  // 20  Vidar Stealer
  // ---------------------------------------------------------------
  {
    name: "Vidar Stealer",
    type: "information stealer",
    description:
      "Information stealer forked from Arkei stealer, widely sold as MaaS. " +
      "Extracts browser data, cryptocurrency wallets, 2FA app data, and can " +
      "capture screenshots. Uses social media profiles (Mastodon, Steam) as " +
      "dead drop resolvers for C2 addresses.",
    iocs: [
      "DLL dependencies fetched from C2 (vcruntime140.dll, sqlite3.dll, etc.)",
      "Configuration fetched from social media profiles (Mastodon, Steam, Telegram)",
      "Data exfiltration via HTTP POST multipart form-data",
      "Targeting of Authy, Google Authenticator 2FA data",
      "Distinctive user-agent patterns in C2 communication",
      "Self-deletion after exfiltration"
    ],
    detection: [
      "YARA rules for Vidar payload signatures",
      "Network monitoring for DLL downloads from suspicious hosts",
      "Behavioral detection of 2FA application data access",
      "Social media profile monitoring for encoded C2 data",
      "HTTP POST monitoring for multipart data exfiltration patterns"
    ]
  },

  // ---------------------------------------------------------------
  // 21  Formbook / XLoader
  // ---------------------------------------------------------------
  {
    name: "Formbook",
    type: "information stealer / form grabber",
    description:
      "Sophisticated information stealer that captures form data, keystrokes, " +
      "clipboard contents, and screenshots. Sold as malware-as-a-service. " +
      "Rebranded as XLoader for macOS targeting. Notable for extensive " +
      "anti-analysis and anti-VM capabilities.",
    iocs: [
      "Process injection via process hollowing (explorer.exe, browser processes)",
      "Decoy C2 domains mixed with real C2 in configuration",
      "SHA1 hash-based string obfuscation",
      "Steganography in PNG images for payload delivery",
      "Anti-analysis: RDTSC timing, CPUID checks, NtQueryInformationProcess",
      "Keylogger data stored in %AppData% before exfiltration"
    ],
    detection: [
      "YARA rules for Formbook/XLoader packer and payload",
      "Behavioral detection of process hollowing sequences",
      "Network monitoring for Formbook C2 URL patterns",
      "Memory forensics for Formbook configuration extraction",
      "Sysmon Event ID 8 for remote thread creation in browser processes"
    ]
  },

  // ---------------------------------------------------------------
  // 22  Gh0st RAT
  // ---------------------------------------------------------------
  {
    name: "Gh0st RAT",
    type: "remote access trojan",
    description:
      "Open-source Chinese-origin remote access trojan widely used since 2008. " +
      "Features remote desktop, keylogging, file management, webcam capture, " +
      "and audio recording. Source code availability has led to numerous " +
      "variants and modifications by multiple threat groups.",
    iocs: [
      "Magic bytes 'Gh0st' or custom header in C2 protocol",
      "Zlib-compressed C2 traffic",
      "Service-based persistence (svchost.exe injection)",
      "Registry key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\<random>",
      "Custom packet header varying by variant (e.g., 'LURK0', 'heart')",
      "DLL injection into system processes"
    ],
    detection: [
      "YARA rules for Gh0st RAT variants",
      "Network signatures for Gh0st protocol magic bytes",
      "Sysmon monitoring for service installation with random names",
      "Behavioral detection of zlib-compressed C2 traffic patterns",
      "Registry monitoring for suspicious service creation"
    ]
  },

  // ---------------------------------------------------------------
  // 23  njRAT
  // ---------------------------------------------------------------
  {
    name: "njRAT",
    type: "remote access trojan",
    description:
      "Widely-used .NET remote access trojan also known as Bladabindi. " +
      "Popular in Middle Eastern cybercrime. Features include keylogging, " +
      "screen capture, webcam access, file theft, and reverse shell. " +
      "Available as a free builder tool.",
    iocs: [
      "Mutex patterns: njq8, njRAT, or custom configurable mutex",
      ".NET binary with characteristic 'OK' configuration delimiter",
      "Registry Run key persistence",
      "TCP communication with base64-encoded commands",
      "Plugin loading via .NET reflection",
      "Keylog data in %TEMP%\\[hash].tmp"
    ],
    detection: [
      "YARA rules for njRAT .NET patterns",
      "Network monitoring for njRAT command protocol",
      "Sysmon monitoring for .NET process creating temp files",
      "Registry monitoring for Run key additions",
      "Behavioral detection of webcam/microphone API access"
    ]
  },

  // ---------------------------------------------------------------
  // 24  DarkComet
  // ---------------------------------------------------------------
  {
    name: "DarkComet",
    type: "remote access trojan",
    description:
      "Feature-rich remote access trojan developed by DarkCoderSc (Jean-Pierre " +
      "Lesueur). Originally a legitimate tool, it became widely abused by threat " +
      "actors including state-sponsored groups. Development halted in 2012 after " +
      "reports of use by Syrian government against activists.",
    iocs: [
      "Mutex: DC_MUTEX-*, DarkComet-*",
      "Registry persistence: HKCU\\Software\\DC3_FEXEC",
      "Process injection and keylogging capabilities",
      "C2 communication with distinctive protocol header",
      "Firewall exception rules added for persistence",
      "File names: svchost.exe, csrss.exe (masquerading)"
    ],
    detection: [
      "YARA rules for DarkComet binary patterns",
      "Registry monitoring for DC3_FEXEC key",
      "Mutex detection: DC_MUTEX prefix",
      "Network monitoring for DarkComet protocol signatures",
      "Behavioral detection of firewall rule modifications"
    ]
  },

  // ---------------------------------------------------------------
  // 25  Dridex
  // ---------------------------------------------------------------
  {
    name: "Dridex",
    type: "banking trojan",
    description:
      "Successor to the Cridex/Bugat banking trojan, operated by Evil Corp " +
      "(INDRIK SPIDER). Sophisticated banking trojan featuring web injects, " +
      "VNC hidden desktop, and P2P-based botnet infrastructure. Major " +
      "distribution vehicle for BitPaymer and DoppelPaymer ransomware.",
    iocs: [
      "Process hollowing into explorer.exe or svchost.exe",
      "P2P botnet communication on high ports",
      "Web inject targeting major banking institutions",
      "AtomBombing code injection technique",
      "Macro-enabled document delivery with AutoOpen triggers",
      "Distinctive XML configuration format"
    ],
    detection: [
      "YARA rules for Dridex loader and core module",
      "Network monitoring for P2P botnet protocol",
      "Behavioral detection of AtomBombing injection",
      "Web traffic monitoring for inject pattern indicators",
      "Process monitoring for hollowed explorer.exe instances"
    ]
  },

  // ---------------------------------------------------------------
  // 26  ZLoader / Zbot / Zeus
  // ---------------------------------------------------------------
  {
    name: "ZLoader",
    type: "banking trojan / loader",
    description:
      "Banking trojan based on leaked Zeus source code. Evolved from " +
      "the original Zeus/Zbot into a distinct malware family. Used for " +
      "credential theft via web injects and as a loader for ransomware " +
      "including Ryuk and DarkSide.",
    iocs: [
      "Web inject configuration targeting banking domains",
      "RSA-signed C2 communication",
      "Persistence via registry and scheduled tasks",
      "Domain generation algorithm (DGA) for backup C2",
      "Man-in-the-browser (MitB) for credential theft",
      "Configuration file encrypted with RC4"
    ],
    detection: [
      "YARA rules for ZLoader decrypted configuration",
      "Network monitoring for DGA domain resolution",
      "Browser hooking detection via API monitoring",
      "Behavioral detection of Man-in-the-Browser activity",
      "Registry monitoring for ZLoader persistence keys"
    ]
  },

  // ---------------------------------------------------------------
  // 27  IcedID / BokBot
  // ---------------------------------------------------------------
  {
    name: "IcedID",
    type: "banking trojan / loader",
    description:
      "Banking trojan that has evolved into a major initial access loader. " +
      "Features web injection for banking credential theft and proxy module " +
      "for man-in-the-browser attacks. Frequently used as precursor to " +
      "ransomware including Conti, REvil, and Quantum.",
    iocs: [
      "GzipLoader initial stage fetching encrypted payload",
      "Fake GZIP headers (1F 8B) in C2 communication",
      "HTTPS C2 with cookie-based data exchange",
      "DLL loaded via regsvr32.exe or rundll32.exe",
      "BackConnect module for VNC, SOCKS proxy, reverse shell",
      "Domain fronting or repurposed legitimate domains for C2"
    ],
    detection: [
      "YARA rules for IcedID GzipLoader and core DLL",
      "Network monitoring for fake GZIP header patterns",
      "Sysmon monitoring for regsvr32/rundll32 loading from temp dirs",
      "SSL/TLS certificate monitoring for IcedID C2 patterns",
      "Behavioral detection of browser injection hooks"
    ]
  },

  // ---------------------------------------------------------------
  // 28  BumbleBee
  // ---------------------------------------------------------------
  {
    name: "BumbleBee",
    type: "loader / initial access",
    description:
      "Sophisticated malware loader that replaced BazarLoader as a primary " +
      "initial access tool. Attributed to Conti/TrickBot ecosystem. Uses " +
      "ISO/VHD delivery, WMI for execution, and deploys Cobalt Strike, " +
      "Sliver, and ransomware payloads.",
    iocs: [
      "ISO or VHD container delivery via email",
      "WMI execution: wmic process call create",
      "DLL loaded via rundll32 with specific exports",
      "Unique User-Agent patterns in C2 communication",
      "Group IDs used for campaign tracking",
      "In-memory Cobalt Strike beacon deployment"
    ],
    detection: [
      "YARA rules for BumbleBee DLL payload",
      "Sysmon monitoring for WMI process creation chains",
      "Network monitoring for BumbleBee C2 protocol patterns",
      "Behavioral detection of ISO mount -> DLL execution chains",
      "Process monitoring for rundll32 with unusual DLL paths"
    ]
  },

  // ---------------------------------------------------------------
  // 29  SystemBC
  // ---------------------------------------------------------------
  {
    name: "SystemBC",
    type: "proxy backdoor / loader",
    description:
      "Proxy-capable backdoor commonly used to provide persistent access and " +
      "hide C2 traffic. Frequently deployed alongside ransomware operations as " +
      "a SOCKS5 proxy for obfuscating traffic. Used by multiple RaaS groups " +
      "including Ryuk, Conti, DarkSide, and REvil affiliates.",
    iocs: [
      "SOCKS5 proxy functionality over Tor",
      "XOR-encrypted C2 communication",
      "Scheduled task or service-based persistence",
      "Small footprint (typically under 50KB)",
      "Configuration embedded in binary (C2 host, port, Tor flag)",
      "Temporary .cmd batch scripts for execution"
    ],
    detection: [
      "YARA rules for SystemBC binary patterns",
      "Network monitoring for Tor traffic from unusual processes",
      "Sysmon monitoring for small executable creating proxy connections",
      "Behavioral detection of SOCKS5 tunnel establishment",
      "Scheduled task monitoring for suspicious .cmd execution"
    ]
  },

  // ---------------------------------------------------------------
  // 30  BazarLoader / BazarBackdoor
  // ---------------------------------------------------------------
  {
    name: "BazarLoader",
    type: "loader / backdoor",
    description:
      "Sophisticated loader from the TrickBot ecosystem (Wizard Spider). " +
      "Used for initial access, reconnaissance, and delivery of post-exploitation " +
      "tools including Cobalt Strike and Ryuk/Conti ransomware. Features " +
      "blockchain-based DNS (EmerDNS) for resilient C2.",
    iocs: [
      "Signed executables for trust evasion",
      "EmerDNS (.bazar TLD) for C2 resolution",
      "HTTPS C2 communication with distinctive patterns",
      "Process hollowing into svchost.exe or cmd.exe",
      "Enterprise-targeting phishing lures (HR, legal, payroll)",
      "File types: .exe, .dll, .iso, .lnk for delivery"
    ],
    detection: [
      "YARA rules for BazarLoader / BazarBackdoor",
      "DNS monitoring for .bazar TLD resolution attempts",
      "Network monitoring for BazarLoader HTTPS C2 patterns",
      "Process monitoring for hollowed svchost.exe instances",
      "Email gateway monitoring for BazarLoader lure patterns"
    ]
  },

  // ---------------------------------------------------------------
  // 31  Sliver
  // ---------------------------------------------------------------
  {
    name: "Sliver",
    type: "command-and-control framework / post-exploitation",
    description:
      "Open-source adversary emulation framework developed by BishopFox. " +
      "Increasingly adopted by threat actors as an alternative to Cobalt Strike. " +
      "Supports multiple C2 protocols (mTLS, WireGuard, HTTP/S, DNS), " +
      "process injection, and cross-platform implants.",
    iocs: [
      "Default mTLS on port 8888",
      "WireGuard-based C2 communication",
      "Go binary with characteristic strings or stripped symbols",
      "Process injection via donut shellcode generation",
      "DNS-based C2 using TXT or CNAME records",
      "Named pipe pivoting for lateral movement"
    ],
    detection: [
      "YARA rules for Sliver implant Go binaries",
      "Network monitoring for mTLS connections on port 8888",
      "JA3 fingerprints for Sliver HTTPS implants",
      "Behavioral detection of Go binary process injection",
      "DNS monitoring for high-entropy subdomain queries"
    ]
  },

  // ---------------------------------------------------------------
  // 32  Brute Ratel C4
  // ---------------------------------------------------------------
  {
    name: "Brute Ratel C4",
    type: "command-and-control framework / post-exploitation",
    description:
      "Commercial adversary simulation framework (BRc4) designed to evade " +
      "endpoint detection. Features include indirect syscalls, ETW patching, " +
      "AMSI bypass, and multiple C2 channels. Cracked versions have been " +
      "adopted by ransomware groups and APTs.",
    iocs: [
      "Badger payloads (BRc4's implant name)",
      "Indirect syscalls to bypass user-mode hooks",
      "ETW patching for event log evasion",
      "C2 over legitimate cloud services (AWS, Azure, Slack)",
      "In-memory .NET assembly loading",
      "Distinctive x64 shellcode stager patterns"
    ],
    detection: [
      "YARA rules for BRc4 badger payload",
      "Behavioral detection of indirect syscall patterns",
      "ETW provider disabling monitoring",
      "Network monitoring for C2 over cloud service APIs",
      "Memory scanning for BRc4 shellcode signatures"
    ]
  },

  // ---------------------------------------------------------------
  // 33  Ursnif / Gozi / ISFB
  // ---------------------------------------------------------------
  {
    name: "Ursnif",
    type: "banking trojan",
    description:
      "Long-running banking trojan also known as Gozi and ISFB. Features " +
      "web injection for credential theft, form grabbing, and VNC hidden " +
      "desktop. Source code leaked multiple times leading to many variants. " +
      "Recent versions pivot toward pure loader/backdoor functionality.",
    iocs: [
      "Web inject configuration targeting banking portals",
      "Serpent (custom encryption) for C2 communication",
      "Persistence via COM object hijacking or scheduled tasks",
      "PowerShell download and execution chain",
      "JOIN/SOFT/CERT configuration identifiers",
      "CAB file payload container"
    ],
    detection: [
      "YARA rules for Ursnif variants (ISFB v2/v3, RM3, LDR4)",
      "Network monitoring for Serpent-encrypted C2 traffic",
      "COM object hijacking detection in registry",
      "Behavioral detection of hidden VNC desktop creation",
      "PowerShell execution monitoring for encoded download cradles"
    ]
  },

  // ---------------------------------------------------------------
  // 34  SmokeLoader
  // ---------------------------------------------------------------
  {
    name: "SmokeLoader",
    type: "loader / backdoor",
    description:
      "Long-running modular loader and backdoor sold on underground forums. " +
      "Used primarily to download and execute additional payloads. Features " +
      "anti-analysis, process injection, and a plugin system for credential " +
      "theft, DDoS, and crypto mining.",
    iocs: [
      "Process injection into explorer.exe",
      "Anti-analysis: API hashing, timing checks, PEB debugging flag",
      "RC4-encrypted C2 communication",
      "Plugins: FormGrabber, FakeLogin, DDoS, Miner",
      "Dynamic API resolution via hashing",
      "Persistence via registry Run key"
    ],
    detection: [
      "YARA rules for SmokeLoader packer and payload",
      "Behavioral detection of explorer.exe injection",
      "Network monitoring for RC4-encrypted C2 patterns",
      "API call monitoring for dynamic resolution patterns",
      "Process monitoring for injection into explorer.exe"
    ]
  },

  // ---------------------------------------------------------------
  // 35  Raspberry Robin
  // ---------------------------------------------------------------
  {
    name: "Raspberry Robin",
    type: "worm / loader",
    description:
      "USB-propagating worm that has become a major initial access vector. " +
      "Spreads via infected USB drives containing malicious LNK files that " +
      "abuse msiexec.exe for payload download. Used to deliver FakeUpdates, " +
      "IcedID, BumbleBee, TrueBot, and Cl0p ransomware.",
    iocs: [
      "Malicious LNK files on USB drives",
      "msiexec.exe /q /i http://[short-domain]/[random] execution",
      "Use of compromised QNAP NAS devices as C2",
      "Tor-based C2 communication",
      "Heavy process injection chain",
      "Living-off-the-land binaries (msiexec, cmd, rundll32, fodhelper)"
    ],
    detection: [
      "Sysmon monitoring for msiexec.exe with URL parameters",
      "USB device monitoring for suspicious LNK file creation",
      "Network monitoring for connections to known compromised QNAP devices",
      "YARA rules for Raspberry Robin payload",
      "Behavioral detection of multi-stage process injection"
    ]
  },

  // ---------------------------------------------------------------
  // 36  Havoc
  // ---------------------------------------------------------------
  {
    name: "Havoc",
    type: "command-and-control framework / post-exploitation",
    description:
      "Open-source post-exploitation command and control framework. " +
      "Features a Demon agent with sleep obfuscation, indirect syscalls, " +
      "token manipulation, and multiple C2 protocols. Growing adoption " +
      "by threat actors as a free alternative to Cobalt Strike.",
    iocs: [
      "Demon agent with sleep mask obfuscation",
      "Indirect syscalls for EDR evasion",
      "HTTP/HTTPS C2 with configurable profiles",
      "Process injection via various techniques",
      "BOF (Beacon Object File) execution capability",
      "Cross-compiled Go/C payloads"
    ],
    detection: [
      "YARA rules for Havoc Demon agent",
      "Memory scanning for sleep obfuscation patterns",
      "Network monitoring for Havoc C2 protocol signatures",
      "Behavioral detection of indirect syscall execution",
      "Process monitoring for unusual shellcode execution"
    ]
  },

  // ---------------------------------------------------------------
  // 37  Amadey
  // ---------------------------------------------------------------
  {
    name: "Amadey",
    type: "loader / botnet",
    description:
      "Lightweight botnet and loader malware sold on Russian-language forums. " +
      "Primary function is system profiling and delivery of secondary payloads. " +
      "Commonly delivers RedLine, Vidar, and various ransomware. Simple but " +
      "effective and continuously updated.",
    iocs: [
      "HTTP POST to /jg34jg/index.php with system info",
      "Persistence via Startup folder LNK or scheduled task",
      "System profiling: GUID, OS version, installed AV, username",
      "Payload download and execution from C2",
      "Anti-analysis: checks for common sandbox usernames",
      "File copy to %AppData% with random directory name"
    ],
    detection: [
      "YARA rules for Amadey loader binary",
      "Network monitoring for /jg34jg/ or similar URI patterns",
      "Sysmon monitoring for file copies to AppData with execution",
      "Behavioral detection of system profiling followed by download",
      "Startup folder monitoring for suspicious LNK creation"
    ]
  },

  // ---------------------------------------------------------------
  // 38  Snake / Uroburos
  // ---------------------------------------------------------------
  {
    name: "Snake",
    type: "espionage platform / rootkit",
    description:
      "Sophisticated espionage toolkit attributed to Turla (Russia FSB). " +
      "Features a custom peer-to-peer network for covert communication, " +
      "kernel-level rootkit for persistence, and modular architecture. " +
      "Active for nearly 20 years before infrastructure takedown in 2023.",
    iocs: [
      "Kernel driver rootkit component",
      "Custom P2P covert communication channel",
      "Encrypted virtual file system for stolen data",
      "Named pipe: \\\\pipe\\YOURNAME",
      "HTTP, TCP, and UDP-based C2 protocols",
      "Distinctive code injection into kernel processes"
    ],
    detection: [
      "YARA rules for Snake kernel driver",
      "Kernel driver signature verification monitoring",
      "Network monitoring for Snake P2P protocol anomalies",
      "Memory forensics for Snake rootkit artifacts",
      "File system forensics for encrypted virtual file system"
    ]
  },

  // ---------------------------------------------------------------
  // 39  Mythic
  // ---------------------------------------------------------------
  {
    name: "Mythic",
    type: "command-and-control framework",
    description:
      "Open-source, cross-platform C2 framework with a modular agent " +
      "architecture. Supports multiple agent types (Apollo, Poseidon, Medusa, " +
      "Athena) across Windows, Linux, and macOS. Web-based operator interface " +
      "with collaborative features. Increasingly seen in real-world intrusions.",
    iocs: [
      "Agent-specific indicators (Apollo .NET, Poseidon Go, Medusa Python)",
      "HTTP/HTTPS C2 with customizable profiles",
      "WebSocket-based C2 communication option",
      "P2P agent communication capabilities",
      "Dynamic payload generation and compilation",
      "Task-based command execution model"
    ],
    detection: [
      "YARA rules for specific Mythic agents",
      "Network monitoring for Mythic C2 protocol patterns",
      "Behavioral detection of agent-specific execution patterns",
      "JA3/JA3S fingerprinting for Mythic HTTPS agents",
      "Process monitoring for characteristic agent behaviors"
    ]
  },

  // ---------------------------------------------------------------
  // 40  Gootloader / GootKit
  // ---------------------------------------------------------------
  {
    name: "Gootloader",
    type: "loader / SEO poisoning",
    description:
      "JavaScript-based loader that uses SEO poisoning to distribute malware " +
      "via compromised WordPress sites. Targets users searching for business " +
      "documents (contracts, agreements, templates). Delivers GootKit banker, " +
      "Cobalt Strike, REvil, and other payloads.",
    iocs: [
      "SEO-poisoned search results linking to compromised WordPress sites",
      "Multi-stage JavaScript execution with obfuscation",
      "Registry-based persistence storing encoded payloads",
      "WScript.exe or cscript.exe JavaScript execution",
      "Heavily obfuscated .js files disguised as documents",
      "PowerShell execution from scheduled tasks"
    ],
    detection: [
      "YARA rules for Gootloader JavaScript stages",
      "Sysmon monitoring for wscript.exe executing from Downloads",
      "Registry monitoring for large encoded values in Run keys",
      "Network monitoring for C2 callback after document download",
      "Behavioral detection of JS -> PowerShell execution chains"
    ]
  },

  // ---------------------------------------------------------------
  // 41  PikaBot
  // ---------------------------------------------------------------
  {
    name: "PikaBot",
    type: "loader / backdoor",
    description:
      "Modular loader malware that emerged as a QakBot successor after the " +
      "FBI takedown. Features a loader and core module with anti-analysis, " +
      "process injection, and flexible C2 protocol. Delivers Cobalt Strike " +
      "and ransomware payloads.",
    iocs: [
      "DLL execution via rundll32 with ordinal export",
      "Heavy anti-analysis: sandbox detection, debugger checks",
      "Process injection via NtWriteVirtualMemory",
      "HTTP/HTTPS C2 with JSON-formatted data",
      "Thread notification delivery (APC injection)",
      "Distinctive packer with multi-layer decryption"
    ],
    detection: [
      "YARA rules for PikaBot packer and core module",
      "Sysmon monitoring for rundll32 ordinal execution",
      "Network monitoring for PikaBot C2 JSON patterns",
      "Behavioral detection of anti-analysis technique chains",
      "Process injection monitoring via ETW"
    ]
  },

  // ---------------------------------------------------------------
  // 42  DarkGate
  // ---------------------------------------------------------------
  {
    name: "DarkGate",
    type: "loader / RAT",
    description:
      "Feature-rich loader and remote access trojan sold as MaaS since 2018 " +
      "but gained prominence in 2023 after QakBot takedown. Features include " +
      "hVNC, crypto mining, keylogging, credential theft, and AnyDesk abuse. " +
      "Distributed via Teams messages, phishing, and malvertising.",
    iocs: [
      "AutoIt or AutoHotKey compiled scripts for execution",
      "Payload hidden in .LNK, .MSI, .VBS, or .HTA files",
      "Microsoft Teams external message delivery vector",
      "hVNC for hidden remote desktop access",
      "Persistence via Run key or scheduled task",
      "C2 communication with custom encryption"
    ],
    detection: [
      "YARA rules for DarkGate AutoIt payload",
      "Sysmon monitoring for AutoIt3.exe or compiled script execution",
      "Network monitoring for DarkGate C2 protocol",
      "Behavioral detection of hVNC hidden desktop creation",
      "Teams message monitoring for external sender abuse"
    ]
  },

  // ---------------------------------------------------------------
  // 43  Lumma Stealer
  // ---------------------------------------------------------------
  {
    name: "Lumma Stealer",
    type: "information stealer",
    description:
      "Sophisticated C-based information stealer sold as MaaS on Telegram " +
      "and underground forums. Targets browser credentials, cryptocurrency " +
      "wallets, 2FA extensions, and other sensitive data. Notable for rapid " +
      "development cycle and advanced anti-detection capabilities.",
    iocs: [
      "C/C++ binary with anti-VM and anti-debug checks",
      "Targeting of 10+ Chromium-based and Firefox browsers",
      "Cryptocurrency wallet extension targeting (50+ wallets)",
      "Steam session file theft",
      "C2 communication via HTTPS with custom encryption",
      "CAPTCHA-based evasion in delivery chain"
    ],
    detection: [
      "YARA rules for Lumma payload structure",
      "Network monitoring for Lumma C2 beacon patterns",
      "Behavioral detection of mass browser data access",
      "File system monitoring for cryptocurrency wallet file access",
      "Process monitoring for rapid credential harvesting sequence"
    ]
  }
];


// ===================================================================
//  3. IOC PATTERNS  (50+)
//  Each entry: { type, pattern, description }
// ===================================================================

const IOC_PATTERNS = [
  // -- IPv4 / IPv6 --
  {
    type: "ipv4",
    pattern: "^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$",
    description: "Standard IPv4 address format"
  },
  {
    type: "ipv4-cidr",
    pattern: "^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\/(?:[0-9]|[12]\\d|3[0-2])$",
    description: "IPv4 address with CIDR notation subnet mask"
  },
  {
    type: "ipv6",
    pattern: "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
    description: "Full IPv6 address (non-abbreviated)"
  },
  {
    type: "ipv6-compressed",
    pattern: "^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$",
    description: "Compressed IPv6 address with double-colon shorthand"
  },

  // -- Hashes --
  {
    type: "md5",
    pattern: "^[a-fA-F0-9]{32}$",
    description: "MD5 hash (128-bit / 32 hex characters)"
  },
  {
    type: "sha1",
    pattern: "^[a-fA-F0-9]{40}$",
    description: "SHA-1 hash (160-bit / 40 hex characters)"
  },
  {
    type: "sha256",
    pattern: "^[a-fA-F0-9]{64}$",
    description: "SHA-256 hash (256-bit / 64 hex characters)"
  },
  {
    type: "sha512",
    pattern: "^[a-fA-F0-9]{128}$",
    description: "SHA-512 hash (512-bit / 128 hex characters)"
  },
  {
    type: "ssdeep",
    pattern: "^\\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+$",
    description: "ssdeep fuzzy hash format (blocksize:hash1:hash2)"
  },
  {
    type: "imphash",
    pattern: "^[a-fA-F0-9]{32}$",
    description: "Import hash (MD5 of import table) for PE executable similarity"
  },
  {
    type: "tlsh",
    pattern: "^T1[a-fA-F0-9]{70}$",
    description: "TLSH (Trend Micro Locality Sensitive Hash) for similarity matching"
  },

  // -- Domains / URLs --
  {
    type: "domain",
    pattern: "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$",
    description: "Fully qualified domain name"
  },
  {
    type: "url",
    pattern: "^https?:\\/\\/[^\\s/$.?#].[^\\s]*$",
    description: "HTTP/HTTPS URL"
  },
  {
    type: "defanged-domain",
    pattern: "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\[\\.](?:[a-zA-Z]{2,})$",
    description: "Defanged domain with [.] notation used in threat reports"
  },
  {
    type: "defanged-url",
    pattern: "^hxxps?:\\/\\/[^\\s]+$",
    description: "Defanged URL with hxxp/hxxps protocol used in threat reports"
  },
  {
    type: "punycode-domain",
    pattern: "^xn--[a-zA-Z0-9-]+\\.(?:[a-zA-Z]{2,})$",
    description: "Punycode-encoded internationalized domain (IDN) for homograph attacks"
  },
  {
    type: "onion-domain",
    pattern: "^[a-z2-7]{56}\\.onion$",
    description: "Tor v3 hidden service (.onion) address (56 chars base32)"
  },

  // -- Email --
  {
    type: "email",
    pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
    description: "Email address format"
  },
  {
    type: "email-header-from",
    pattern: "^From:\\s*.*<[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+>",
    description: "Email From header with display name and address"
  },
  {
    type: "email-header-received",
    pattern: "^Received:\\s+from\\s+\\S+",
    description: "Email Received header for tracing delivery path"
  },

  // -- File paths --
  {
    type: "windows-filepath",
    pattern: "^[a-zA-Z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)*[^\\\\/:*?\"<>|\\r\\n]*$",
    description: "Windows file path with drive letter"
  },
  {
    type: "unix-filepath",
    pattern: "^\\/(?:[^\\/\\0]+\\/)*[^\\/\\0]*$",
    description: "Unix/Linux absolute file path"
  },
  {
    type: "unc-path",
    pattern: "^\\\\\\\\[a-zA-Z0-9._-]+\\\\[a-zA-Z0-9$._-]+",
    description: "UNC network path (\\\\server\\share)"
  },

  // -- Registry --
  {
    type: "registry-key",
    pattern: "^(?:HKLM|HKCU|HKCR|HKU|HKCC)\\\\[^\\\\].*$",
    description: "Windows registry key path"
  },
  {
    type: "registry-value",
    pattern: "^(?:HKLM|HKCU|HKCR|HKU|HKCC)\\\\.*\\\\[^\\\\]+$",
    description: "Windows registry value path (key + value name)"
  },

  // -- Cryptocurrency --
  {
    type: "bitcoin-address",
    pattern: "^(?:1[1-9A-HJ-NP-Za-km-z]{25,34}|3[1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})$",
    description: "Bitcoin address (Legacy P2PKH, P2SH, or Bech32 format)"
  },
  {
    type: "ethereum-address",
    pattern: "^0x[a-fA-F0-9]{40}$",
    description: "Ethereum address (0x-prefixed, 40 hex characters)"
  },
  {
    type: "monero-address",
    pattern: "^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$",
    description: "Monero (XMR) address (95 characters, starts with 4)"
  },
  {
    type: "bitcoin-transaction",
    pattern: "^[a-fA-F0-9]{64}$",
    description: "Bitcoin transaction hash (64 hex characters, same format as SHA-256)"
  },

  // -- CVE / Vulnerability --
  {
    type: "cve-id",
    pattern: "^CVE-\\d{4}-\\d{4,}$",
    description: "CVE vulnerability identifier (CVE-YEAR-NUMBER)"
  },
  {
    type: "cwe-id",
    pattern: "^CWE-\\d{1,4}$",
    description: "CWE weakness identifier"
  },
  {
    type: "cpe",
    pattern: "^cpe:2\\.3:[aho\\*]:[^:]+:[^:]+:[^:]+",
    description: "CPE 2.3 (Common Platform Enumeration) identifier"
  },

  // -- Network artifacts --
  {
    type: "user-agent",
    pattern: "^Mozilla\\/\\d\\.\\d\\s+\\([^)]+\\).*$",
    description: "HTTP User-Agent string pattern"
  },
  {
    type: "ja3-fingerprint",
    pattern: "^[a-fA-F0-9]{32}$",
    description: "JA3 TLS client fingerprint (MD5 hash)"
  },
  {
    type: "ja3s-fingerprint",
    pattern: "^[a-fA-F0-9]{32}$",
    description: "JA3S TLS server fingerprint (MD5 hash)"
  },
  {
    type: "jarm-fingerprint",
    pattern: "^[a-fA-F0-9]{62}$",
    description: "JARM active TLS server fingerprint (62 hex characters)"
  },
  {
    type: "mac-address",
    pattern: "^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$",
    description: "MAC address in colon or dash-separated format"
  },
  {
    type: "asn",
    pattern: "^AS\\d{1,10}$",
    description: "Autonomous System Number (AS prefix + digits)"
  },

  // -- MITRE ATT&CK --
  {
    type: "mitre-technique",
    pattern: "^T\\d{4}(?:\\.\\d{3})?$",
    description: "MITRE ATT&CK technique ID (e.g., T1059 or T1059.001)"
  },
  {
    type: "mitre-tactic",
    pattern: "^TA\\d{4}$",
    description: "MITRE ATT&CK tactic ID (e.g., TA0001)"
  },
  {
    type: "mitre-software",
    pattern: "^S\\d{4}$",
    description: "MITRE ATT&CK software ID (e.g., S0154)"
  },
  {
    type: "mitre-group",
    pattern: "^G\\d{4}$",
    description: "MITRE ATT&CK group ID (e.g., G0007)"
  },

  // -- YARA / Sigma --
  {
    type: "yara-rule-name",
    pattern: "^rule\\s+[a-zA-Z_][a-zA-Z0-9_]*",
    description: "YARA rule definition name"
  },
  {
    type: "sigma-rule-id",
    pattern: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    description: "Sigma rule UUID identifier"
  },

  // -- PE / ELF artifacts --
  {
    type: "pe-imphash",
    pattern: "^[a-fA-F0-9]{32}$",
    description: "PE file import hash for binary similarity matching"
  },
  {
    type: "pe-compilation-timestamp",
    pattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}",
    description: "PE compilation timestamp (ISO 8601 format)"
  },
  {
    type: "pe-section-hash",
    pattern: "^\\.[a-zA-Z0-9_]+:[a-fA-F0-9]{64}$",
    description: "PE section name with SHA-256 hash (e.g., .text:abc123...)"
  },
  {
    type: "elf-magic",
    pattern: "^7f454c46",
    description: "ELF binary magic bytes (\\x7fELF)"
  },

  // -- SSL/TLS --
  {
    type: "ssl-certificate-serial",
    pattern: "^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})*$",
    description: "SSL/TLS certificate serial number in colon-separated hex"
  },
  {
    type: "ssl-certificate-sha256",
    pattern: "^[a-fA-F0-9]{64}$",
    description: "SSL/TLS certificate SHA-256 fingerprint"
  },
  {
    type: "ssl-subject-cn",
    pattern: "^CN=[^,]+",
    description: "SSL certificate Subject Common Name field"
  },

  // -- STIX / OpenIOC --
  {
    type: "stix-id",
    pattern: "^[a-z-]+--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    description: "STIX 2.x object identifier (type--UUID)"
  },

  // -- Windows artifacts --
  {
    type: "mutex-name",
    pattern: "^(?:Global|Local)\\\\[A-Za-z0-9_-]+",
    description: "Windows named mutex (Global or Local namespace)"
  },
  {
    type: "named-pipe",
    pattern: "^\\\\\\\\.\\\\pipe\\\\[^\\\\]+$",
    description: "Windows named pipe path"
  },
  {
    type: "windows-service",
    pattern: "^(?:HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\)[a-zA-Z0-9_-]+$",
    description: "Windows service registry path"
  },
  {
    type: "scheduled-task",
    pattern: "^\\\\[a-zA-Z0-9_-]+(?:\\\\[a-zA-Z0-9_-]+)*$",
    description: "Windows scheduled task path (e.g., \\Microsoft\\Windows\\TaskName)"
  },
  {
    type: "wmi-subscription",
    pattern: "^(?:__EventFilter|__EventConsumer|__FilterToConsumerBinding)",
    description: "WMI event subscription class name for persistence detection"
  },

  // -- Cloud / SaaS --
  {
    type: "aws-access-key",
    pattern: "^AKIA[0-9A-Z]{16}$",
    description: "AWS access key ID (starts with AKIA, 20 characters)"
  },
  {
    type: "aws-secret-key",
    pattern: "^[A-Za-z0-9/+=]{40}$",
    description: "AWS secret access key (40 base64 characters)"
  },
  {
    type: "gcp-service-account",
    pattern: "^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]*\\.iam\\.gserviceaccount\\.com$",
    description: "Google Cloud service account email format"
  },
  {
    type: "azure-tenant-id",
    pattern: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    description: "Azure AD tenant ID (UUID format)"
  }
];


// ===================================================================
//  4. THREAT FEEDS  (25+)
//  Each entry: { name, url, type, format, description, free }
// ===================================================================

const THREAT_FEEDS = [
  {
    name: "AlienVault OTX",
    url: "https://otx.alienvault.com",
    type: "multi-ioc",
    format: "JSON / STIX / CSV",
    description:
      "Open Threat Exchange (OTX) is a community-driven threat intelligence " +
      "platform. Aggregates pulses containing IOCs from security researchers " +
      "and organizations worldwide. Provides API access for automated integration.",
    free: true
  },
  {
    name: "Abuse.ch URLhaus",
    url: "https://urlhaus.abuse.ch",
    type: "url",
    format: "CSV / JSON / API",
    description:
      "Community-driven project collecting and sharing malicious URLs used for " +
      "malware distribution. Provides bulk downloads, API access, and real-time " +
      "feeds of active malware distribution sites.",
    free: true
  },
  {
    name: "Abuse.ch MalwareBazaar",
    url: "https://bazaar.abuse.ch",
    type: "malware-sample",
    format: "API / CSV",
    description:
      "Malware sample sharing platform allowing security researchers to upload " +
      "and download malware samples. Provides hash lookups, YARA rule matching, " +
      "and tagged sample collections.",
    free: true
  },
  {
    name: "Abuse.ch ThreatFox",
    url: "https://threatfox.abuse.ch",
    type: "multi-ioc",
    format: "JSON / CSV / API",
    description:
      "Platform for sharing IOCs associated with malware families. Covers IPs, " +
      "domains, URLs, and hashes with malware family attribution. Supports " +
      "bulk export and API queries.",
    free: true
  },
  {
    name: "Abuse.ch Feodo Tracker",
    url: "https://feodotracker.abuse.ch",
    type: "botnet-c2",
    format: "CSV / JSON",
    description:
      "Tracks Command and Control servers of banking trojans including Dridex, " +
      "Emotet, TrickBot, QakBot, and BumbleBee. Provides blocklists of active " +
      "C2 infrastructure.",
    free: true
  },
  {
    name: "Abuse.ch SSL Blacklist (SSLBL)",
    url: "https://sslbl.abuse.ch",
    type: "ssl-certificate",
    format: "CSV / JSON",
    description:
      "Identifies and tracks SSL certificates associated with malware and botnet " +
      "C2 communication. Provides JA3 fingerprints and certificate SHA1 hashes " +
      "for detection.",
    free: true
  },
  {
    name: "VirusTotal",
    url: "https://www.virustotal.com",
    type: "multi-ioc",
    format: "JSON API",
    description:
      "Multi-engine malware scanning service analyzing files, URLs, domains, " +
      "and IPs using 70+ antivirus engines. Premium API provides threat intel " +
      "enrichment, retrohunting (YARA), and relationship graphing.",
    free: false
  },
  {
    name: "MISP Default Feeds",
    url: "https://www.misp-project.org/feeds",
    type: "multi-ioc",
    format: "MISP JSON / STIX",
    description:
      "Collection of default threat intelligence feeds for the MISP platform. " +
      "Includes CIRCL OSINT, Botvrij, and various community feeds providing " +
      "IOCs, threat actors, and malware family data.",
    free: true
  },
  {
    name: "PhishTank",
    url: "https://phishtank.org",
    type: "phishing",
    format: "CSV / XML / JSON",
    description:
      "Community-driven phishing URL verification and collection platform. " +
      "Provides verified phishing URLs with submission metadata and targeting " +
      "information. API available for lookups.",
    free: true
  },
  {
    name: "Emerging Threats (Proofpoint)",
    url: "https://rules.emergingthreats.net",
    type: "ids-rules",
    format: "Suricata / Snort rules",
    description:
      "Open rulesets for Suricata and Snort IDS/IPS. Covers malware C2 " +
      "communication, exploit attempts, and protocol anomalies. ET OPEN " +
      "ruleset is free; ET PRO is commercial.",
    free: true
  },
  {
    name: "Cisco Talos Intelligence",
    url: "https://talosintelligence.com",
    type: "multi-ioc",
    format: "Web / API",
    description:
      "Threat intelligence from Cisco Talos covering IP/domain reputation, " +
      "email reputation, file reputation, and vulnerability intelligence. " +
      "Blog provides detailed threat analysis and campaign reports.",
    free: true
  },
  {
    name: "CrowdStrike Falcon Intel",
    url: "https://www.crowdstrike.com/falcon-platform/threat-intelligence",
    type: "multi-ioc",
    format: "JSON API / STIX",
    description:
      "Commercial threat intelligence providing detailed adversary profiles, " +
      "IOCs, malware analysis, and strategic intelligence. Tracks 200+ threat " +
      "actors with proprietary naming convention.",
    free: false
  },
  {
    name: "Mandiant Threat Intelligence",
    url: "https://www.mandiant.com/advantage/threat-intelligence",
    type: "multi-ioc",
    format: "JSON API / STIX",
    description:
      "Commercial threat intelligence from Google Mandiant combining frontline " +
      "incident response data with proactive research. Covers threat actors, " +
      "malware, vulnerabilities, and campaigns.",
    free: false
  },
  {
    name: "Recorded Future",
    url: "https://www.recordedfuture.com",
    type: "multi-ioc",
    format: "JSON API / STIX",
    description:
      "Commercial threat intelligence platform using AI/ML to analyze open, " +
      "dark, and technical web sources. Provides risk scores, real-time " +
      "alerts, and integration with security tools.",
    free: false
  },
  {
    name: "Shodan",
    url: "https://www.shodan.io",
    type: "infrastructure",
    format: "JSON API",
    description:
      "Internet-wide scanning platform that indexes services, banners, and " +
      "configurations of internet-connected devices. Useful for identifying " +
      "exposed C2 infrastructure, vulnerable devices, and threat actor infrastructure.",
    free: true
  },
  {
    name: "Censys",
    url: "https://censys.io",
    type: "infrastructure",
    format: "JSON API",
    description:
      "Internet-wide scanning platform providing detailed host and certificate " +
      "data. Useful for tracking threat actor infrastructure, identifying " +
      "C2 servers, and mapping attack surfaces.",
    free: true
  },
  {
    name: "GreyNoise",
    url: "https://www.greynoise.io",
    type: "ip-reputation",
    format: "JSON API",
    description:
      "Internet background noise analysis platform that distinguishes between " +
      "targeted attacks and mass scanning. Provides context on IPs conducting " +
      "internet-wide scanning, reducing false positives.",
    free: true
  },
  {
    name: "CISA Known Exploited Vulnerabilities",
    url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    type: "vulnerability",
    format: "JSON / CSV",
    description:
      "US CISA catalog of vulnerabilities with known active exploitation. " +
      "Provides CVE IDs, vendor/product, descriptions, and remediation " +
      "due dates. Updated regularly as new exploited CVEs are confirmed.",
    free: true
  },
  {
    name: "Spamhaus Block Lists",
    url: "https://www.spamhaus.org",
    type: "ip-reputation / domain",
    format: "DNS-based / CSV",
    description:
      "Industry-standard blocklists covering spam sources (SBL), exploited " +
      "hosts (XBL), policy-based blocks (PBL), and domain reputation (DBL). " +
      "DNS-based queries for real-time lookup.",
    free: true
  },
  {
    name: "OpenPhish",
    url: "https://openphish.com",
    type: "phishing",
    format: "text / JSON",
    description:
      "Automated phishing intelligence platform providing URLs of active " +
      "phishing sites. Free community feed provides recent phishing URLs; " +
      "premium feed includes brand targeting and page screenshots.",
    free: true
  },
  {
    name: "Pulsedive",
    url: "https://pulsedive.com",
    type: "multi-ioc",
    format: "JSON API",
    description:
      "Threat intelligence platform that enriches IOCs with passive DNS, " +
      "WHOIS, SSL, and open-source intelligence. Community-driven with " +
      "risk scoring and threat correlation.",
    free: true
  },
  {
    name: "InQuest Labs",
    url: "https://labs.inquest.net",
    type: "file-analysis",
    format: "JSON API",
    description:
      "Threat intelligence platform specializing in deep file inspection " +
      "of documents, emails, and archives. Provides YARA signature matching, " +
      "DFI (Deep File Inspection) analysis, and IOC reputation.",
    free: true
  },
  {
    name: "ThreatConnect",
    url: "https://threatconnect.com",
    type: "multi-ioc",
    format: "JSON API / STIX / TAXII",
    description:
      "Commercial threat intelligence platform combining IOC management, " +
      "threat analysis, and orchestration. Supports STIX/TAXII for automated " +
      "sharing and integration with SIEM/SOAR platforms.",
    free: false
  },
  {
    name: "MITRE ATT&CK",
    url: "https://attack.mitre.org",
    type: "ttp-framework",
    format: "STIX / JSON / Excel",
    description:
      "Knowledge base of adversary tactics, techniques, and procedures (TTPs). " +
      "Covers Enterprise, Mobile, and ICS domains. De facto standard for " +
      "threat behavior classification and detection engineering.",
    free: true
  },
  {
    name: "C2IntelFeeds",
    url: "https://github.com/drb-ra/C2IntelFeeds",
    type: "botnet-c2",
    format: "CSV / text",
    description:
      "Open-source feed of known Command and Control framework infrastructure " +
      "including Cobalt Strike, Metasploit, Mythic, Sliver, Brute Ratel, " +
      "Havoc, and other C2 servers detected via fingerprinting.",
    free: true
  },
  {
    name: "RansomWatch",
    url: "https://ransomwatch.telemetry.ltd",
    type: "ransomware",
    format: "JSON / Web",
    description:
      "Monitoring service tracking ransomware group leak sites on Tor. " +
      "Provides real-time updates on new victims posted by ransomware " +
      "operators across 100+ active groups.",
    free: true
  },
  {
    name: "Botnet Tracker by SecurityScorecard",
    url: "https://botnet-tracker.securityscorecard.com",
    type: "botnet-c2",
    format: "Web",
    description:
      "Tracks active botnet C2 infrastructure including Dridex, Qakbot, " +
      "TrickBot, and other botnet families. Provides geolocation and " +
      "ASN information for C2 servers.",
    free: true
  },
  {
    name: "DigitalSide Threat-Intel",
    url: "https://osint.digitalside.it",
    type: "multi-ioc",
    format: "STIX / CSV / MISP",
    description:
      "Open-source threat intelligence feed providing IOCs extracted from " +
      "malware analysis, OSINT sources, and community submissions. " +
      "Includes IPs, URLs, domains, and file hashes.",
    free: true
  },
  {
    name: "Malpedia",
    url: "https://malpedia.caad.fkie.fraunhofer.de",
    type: "malware-reference",
    format: "Web / API",
    description:
      "Curated malware encyclopedia maintained by Fraunhofer FKIE. Provides " +
      "malware family profiles, YARA rules, references, and actor attribution. " +
      "Links to academic and industry analysis reports.",
    free: true
  }
];


// ===================================================================
//  5. RANSOMWARE GROUPS  (20+)
//  Each entry: { name, firstSeen, encryptionMethod, decryptorAvailable }
// ===================================================================

const RANSOMWARE_GROUPS = [
  {
    name: "LockBit",
    firstSeen: "September 2019",
    encryptionMethod:
      "AES-256-CBC for file encryption with RSA-2048 key wrapping. " +
      "LockBit 3.0 uses intermittent encryption (encrypting every 16th byte " +
      "for large files) for speed. Multi-threaded encryption via I/O completion ports.",
    decryptorAvailable:
      "Partial. LockBit 3.0 builder was leaked in September 2022, enabling " +
      "decryption of files locked with that specific builder configuration. " +
      "Operation Cronos (Feb 2024) yielded 1,000+ decryption keys."
  },
  {
    name: "ALPHV / BlackCat",
    firstSeen: "November 2021",
    encryptionMethod:
      "Written in Rust. Uses AES-128 or ChaCha20 for file encryption with " +
      "RSA-4096 or Ed25519 key exchange. Supports intermittent, fast, full, " +
      "and auto encryption modes. Cross-platform (Windows, Linux, VMware ESXi).",
    decryptorAvailable:
      "Limited. FBI obtained decryption keys during December 2023 seizure " +
      "enabling decryption for some victims. No universal decryptor available."
  },
  {
    name: "Cl0p",
    firstSeen: "February 2019",
    encryptionMethod:
      "RSA-1024 public key encrypted per-file AES-256 keys. Targets specific " +
      "file extensions while avoiding system files. Recently pivoted to " +
      "data theft and extortion without encryption (MOVEit campaign).",
    decryptorAvailable:
      "No universal decryptor. A flawed variant from 2021 allowed partial " +
      "recovery for some victims. Post-2021 variants have no known weaknesses."
  },
  {
    name: "Royal / BlackSuit",
    firstSeen: "September 2022 (Royal) / May 2023 (rebranded BlackSuit)",
    encryptionMethod:
      "AES-256 for file encryption with RSA-2048 key wrapping. Intermittent " +
      "encryption with configurable percentage (default 50%). Targets Windows " +
      "and Linux (VMware ESXi) environments.",
    decryptorAvailable:
      "No publicly available decryptor. Derived from Conti codebase."
  },
  {
    name: "Black Basta",
    firstSeen: "April 2022",
    encryptionMethod:
      "XChaCha20 for file encryption with RSA-4096 key wrapping. Uses " +
      "intermittent encryption (encrypting 64 bytes of every 128 bytes). " +
      "Targets Windows and Linux (VMware ESXi).",
    decryptorAvailable:
      "Partial. SRLabs released a decryptor (Black Basta Buster) in January " +
      "2024 exploiting a flaw in versions prior to December 2023. Fixed in " +
      "newer variants."
  },
  {
    name: "Akira",
    firstSeen: "March 2023",
    encryptionMethod:
      "CryptGenRandom for key generation, ChaCha20 for file encryption, " +
      "RSA-4096 for key wrapping. Uses intermittent encryption. Targets " +
      "Windows and Linux systems including VMware ESXi.",
    decryptorAvailable:
      "Limited. Avast released a free decryptor in June 2023 for early " +
      "variants. Fixed in subsequent versions. GPU-based brute force " +
      "approach demonstrated for older Linux variant."
  },
  {
    name: "Play (PlayCrypt)",
    firstSeen: "June 2022",
    encryptionMethod:
      "AES-RSA hybrid encryption. Intermittent encryption for files over 0.5GB. " +
      "Appends .play extension. Known for exploiting FortiOS and Microsoft " +
      "Exchange vulnerabilities for initial access.",
    decryptorAvailable:
      "No publicly available decryptor."
  },
  {
    name: "Rhysida",
    firstSeen: "May 2023",
    encryptionMethod:
      "ChaCha20 for file encryption with RSA-4096 key encapsulation. " +
      "Intermittent encryption with 3-block skip pattern. Targets Windows " +
      "and Linux. Written in C++ with LibTomCrypt.",
    decryptorAvailable:
      "Yes, for earlier versions. Korean researchers (KISA) released a " +
      "decryptor exploiting flawed CSPRNG implementation. Fixed in later versions."
  },
  {
    name: "Medusa",
    firstSeen: "June 2021",
    encryptionMethod:
      "AES-256-CBC for file encryption with RSA-2048 key wrapping. Multi-threaded " +
      "encryption engine. Appends .MEDUSA extension. Operates as ransomware-as-a-service.",
    decryptorAvailable:
      "No publicly available decryptor."
  },
  {
    name: "BianLian",
    firstSeen: "June 2022",
    encryptionMethod:
      "AES-256-CBC with RSA public key for key wrapping. Initially full " +
      "encryption. Pivoted to data exfiltration-only extortion model in " +
      "early 2023 after Avast decryptor release.",
    decryptorAvailable:
      "Yes. Avast released a free decryptor in January 2023. Group subsequently " +
      "abandoned encryption in favor of pure data exfiltration extortion."
  },
  {
    name: "Vice Society",
    firstSeen: "June 2021",
    encryptionMethod:
      "Uses multiple third-party ransomware strains: HelloKitty/FiveHands, " +
      "Zeppelin, and a custom PolyVice encryptor. PolyVice uses NTRUEncrypt " +
      "with ChaCha20-Poly1305 for fast hybrid encryption.",
    decryptorAvailable:
      "No universal decryptor. Depends on the specific variant deployed."
  },
  {
    name: "Hive",
    firstSeen: "June 2021",
    encryptionMethod:
      "Multiple versions. V1 used Golang with AES encryption. Subsequent " +
      "versions rewritten in Rust with improved encryption. Targets Windows, " +
      "Linux, FreeBSD, and VMware ESXi.",
    decryptorAvailable:
      "Yes. FBI infiltrated the Hive network and obtained decryption keys, " +
      "providing them to 1,300+ victims. Infrastructure seized January 2023."
  },
  {
    name: "REvil / Sodinokibi",
    firstSeen: "April 2019",
    encryptionMethod:
      "Salsa20 (stream cipher) for file encryption with Curve25519 ECDH " +
      "key exchange. Per-file unique key derivation. Configuration stored " +
      "as encrypted JSON resource in PE.",
    decryptorAvailable:
      "Yes, for some versions. Bitdefender released a universal decryptor " +
      "in September 2021 covering all pre-July 2021 infections. Post-relaunch " +
      "versions have no known decryptor."
  },
  {
    name: "Conti",
    firstSeen: "May 2020",
    encryptionMethod:
      "ChaCha20 for file encryption with RSA-4096 key wrapping. Multi-threaded " +
      "with 32 simultaneous threads. Intermittent encryption for speed. " +
      "Source code leaked in March 2022.",
    decryptorAvailable:
      "Partial. Source code leak enabled creation of decryptors for specific " +
      "builds. Conti team members released some keys during dissolution."
  },
  {
    name: "DarkSide / BlackMatter",
    firstSeen: "August 2020 (DarkSide) / July 2021 (BlackMatter)",
    encryptionMethod:
      "Salsa20 for file encryption with RSA-1024 key wrapping. Customizable " +
      "encryption mode: full, fast (first 1MB), or auto (size-based). " +
      "Multithreaded with I/O completion ports.",
    decryptorAvailable:
      "Yes. Emsisoft released a BlackMatter decryptor exploiting a " +
      "cryptographic weakness. Fixed in later builds before group shutdown."
  },
  {
    name: "Ragnar Locker",
    firstSeen: "December 2019",
    encryptionMethod:
      "Salsa20 for file encryption with RSA-2048 key wrapping. Deploys " +
      "inside a Windows XP virtual machine (VirtualBox) to evade endpoint " +
      "detection. Targets large enterprises.",
    decryptorAvailable:
      "No publicly available decryptor. Group's infrastructure seized by " +
      "Europol in October 2023."
  },
  {
    name: "Phobos",
    firstSeen: "December 2018",
    encryptionMethod:
      "AES-256-CBC for file encryption with RSA-1024 key wrapping. Based on " +
      "Dharma/CrySis ransomware codebase. Low ransom demands targeting " +
      "small and medium businesses.",
    decryptorAvailable:
      "No universal public decryptor. Some older variants (Dharma-based) " +
      "have decryptors available. Suspected operator Evgenii Ptitsyn indicted " +
      "by US DOJ in 2024."
  },
  {
    name: "Cuba (COLDDRAW)",
    firstSeen: "December 2019",
    encryptionMethod:
      "ChaCha20 for file encryption with RSA-4096 key wrapping. Selective " +
      "encryption targeting specific file extensions. Partners with " +
      "RomCom/Tropical Scorpius for initial access.",
    decryptorAvailable:
      "No publicly available decryptor."
  },
  {
    name: "NoEscape (Avaddon rebrand)",
    firstSeen: "May 2023",
    encryptionMethod:
      "ChaCha20 for file encryption with RSA key exchange. Written in " +
      "C++ and Rust. Supports Windows, Linux, and VMware ESXi. Triple " +
      "extortion model (encryption + data leak + DDoS).",
    decryptorAvailable:
      "No publicly available decryptor. Reportedly exit-scammed affiliates " +
      "in November 2023."
  },
  {
    name: "8Base",
    firstSeen: "March 2022",
    encryptionMethod:
      "Uses a modified Phobos ransomware variant with AES-256 encryption " +
      "and RSA-1024 key wrapping. Double extortion with leak site. " +
      "Targets small to mid-sized businesses.",
    decryptorAvailable:
      "No publicly available decryptor. Group infrastructure disrupted by " +
      "law enforcement in early 2025."
  },
  {
    name: "Hunters International",
    firstSeen: "October 2023",
    encryptionMethod:
      "Derived from Hive ransomware source code. Uses Rust-based encryption " +
      "with hybrid AES + asymmetric key scheme. Multi-platform targeting " +
      "Windows, Linux, and VMware ESXi.",
    decryptorAvailable:
      "No publicly available decryptor."
  },
  {
    name: "INC Ransom",
    firstSeen: "July 2023",
    encryptionMethod:
      "AES-128-CTR combined with Curve25519 ECDH key exchange. Written in " +
      "C++. Partial encryption for large files. Targets Windows and Linux " +
      "(VMware ESXi) environments.",
    decryptorAvailable:
      "No publicly available decryptor."
  },
  {
    name: "RansomHub",
    firstSeen: "February 2024",
    encryptionMethod:
      "ChaCha20 or AES-256 encryption (configurable) with Curve25519 " +
      "key exchange. Written in Go and C++. Cross-platform support for " +
      "Windows, Linux, VMware ESXi. Intermittent or full encryption modes.",
    decryptorAvailable:
      "No publicly available decryptor. Emerged post-ALPHV disruption " +
      "as a major RaaS operation."
  },
  {
    name: "Cactus",
    firstSeen: "March 2023",
    encryptionMethod:
      "OpenSSL AES-256-CTR for file encryption with RSA-4096 key wrapping. " +
      "Self-encrypting binary requiring a key parameter for execution " +
      "(anti-sandbox technique). Targets VPN appliance vulnerabilities.",
    decryptorAvailable:
      "No publicly available decryptor."
  }
];


// ===================================================================
//  6. ATTACK CAMPAIGNS  (15+)
//  Each entry: { name, actor, year, description, vector, impact }
// ===================================================================

const ATTACK_CAMPAIGNS = [
  {
    name: "SolarWinds Supply Chain Attack",
    actor: "APT29 / Cozy Bear",
    year: 2020,
    description:
      "Sophisticated supply chain attack that compromised SolarWinds Orion " +
      "IT management software. Malicious SUNBURST backdoor was inserted into " +
      "legitimate software updates distributed to approximately 18,000 " +
      "organizations. Follow-on intrusions targeted approximately 100 select " +
      "organizations including US government agencies (Treasury, Commerce, " +
      "Homeland Security) and major technology firms.",
    vector: "Software supply chain compromise via trojanized update",
    impact:
      "18,000 organizations received malicious update. Approximately 100 " +
      "organizations experienced follow-on intrusion. 9 US federal agencies " +
      "and approximately 100 private sector entities significantly impacted. " +
      "Prompted Executive Order 14028 on improving cybersecurity."
  },
  {
    name: "Colonial Pipeline Ransomware",
    actor: "DarkSide",
    year: 2021,
    description:
      "Ransomware attack that shut down the largest fuel pipeline in the " +
      "United States for six days. The Colonial Pipeline, which carries 45% " +
      "of East Coast fuel supply, was taken offline after DarkSide ransomware " +
      "compromised business IT systems. Company paid $4.4M ransom (partially " +
      "recovered by FBI).",
    vector: "Compromised VPN credentials (single-factor, no MFA)",
    impact:
      "Six-day pipeline shutdown. Fuel shortages across southeastern US. " +
      "Gas price spike. $4.4M ransom paid ($2.3M recovered). State of " +
      "emergency declared in 17 states. Accelerated OT security regulations."
  },
  {
    name: "Kaseya VSA Supply Chain Attack",
    actor: "REvil / Sodinokibi",
    year: 2021,
    description:
      "Supply chain ransomware attack exploiting zero-day vulnerabilities " +
      "in Kaseya VSA remote monitoring and management software. Through " +
      "compromised MSPs, the attack cascaded to between 800 and 1,500 " +
      "downstream businesses. REvil demanded $70M for a universal decryptor.",
    vector: "Zero-day exploitation of Kaseya VSA (CVE-2021-30116 and related)",
    impact:
      "800-1,500 downstream businesses affected through approximately 60 " +
      "MSPs. Swedish grocery chain Coop closed 800 stores. $70M ransom " +
      "demanded. Universal decryption key obtained (source debated) and " +
      "distributed to victims."
  },
  {
    name: "NotPetya",
    actor: "Sandworm (GRU Unit 74455)",
    year: 2017,
    description:
      "Destructive wiper disguised as ransomware, initially spread via " +
      "compromised Ukrainian tax software M.E.Doc. Used EternalBlue and " +
      "credential harvesting for lateral movement. Despite appearing to be " +
      "ransomware, the encryption was irreversible by design, making it a " +
      "wiper. Caused the most expensive cyberattack in history.",
    vector: "Software supply chain (M.E.Doc) + EternalBlue worm propagation",
    impact:
      "Estimated $10 billion in global damages. Maersk: $300M (rebuilt " +
      "entire infrastructure). Merck: $870M. FedEx/TNT: $400M. Reckitt " +
      "Benckiser, Mondelez, Saint-Gobain heavily impacted. Multiple " +
      "Ukrainian government and infrastructure systems destroyed."
  },
  {
    name: "WannaCry",
    actor: "Lazarus Group (North Korea)",
    year: 2017,
    description:
      "Global ransomware worm that exploited EternalBlue (MS17-010) to " +
      "propagate through unpatched Windows SMB. Infected over 300,000 " +
      "computers across 150 countries in a single day. Accidentally " +
      "contained when researcher Marcus Hutchins registered the kill " +
      "switch domain.",
    vector: "EternalBlue SMB worm (self-propagating, no user interaction)",
    impact:
      "300,000+ systems across 150 countries. UK NHS: 80 trusts affected, " +
      "19,000 appointments cancelled, estimated $100M cost. Total global " +
      "damages estimated $4-8 billion. Attackers collected only ~$140K " +
      "in Bitcoin despite scale."
  },
  {
    name: "Microsoft Exchange ProxyLogon",
    actor: "Hafnium (initially), followed by multiple groups",
    year: 2021,
    description:
      "Mass exploitation of four zero-day vulnerabilities in Microsoft " +
      "Exchange Server (CVE-2021-26855, 26857, 26858, 27065). Hafnium " +
      "initially exploited them quietly for espionage, but after disclosure, " +
      "multiple threat groups raced to exploit before patching. Web shells " +
      "planted on tens of thousands of Exchange servers worldwide.",
    vector: "Zero-day exploitation of on-premises Microsoft Exchange servers",
    impact:
      "Estimated 250,000+ Exchange servers compromised globally. At least " +
      "30,000 US organizations affected. Web shells provided persistent " +
      "backdoor access. Multiple ransomware groups leveraged access for " +
      "DearCry and Black Kingdom ransomware."
  },
  {
    name: "MOVEit Transfer Exploitation",
    actor: "Cl0p (TA505)",
    year: 2023,
    description:
      "Mass exploitation of SQL injection zero-day (CVE-2023-34362) in " +
      "Progress MOVEit Transfer file transfer software. Cl0p gang " +
      "exfiltrated data from hundreds of organizations and used pure " +
      "data extortion (no encryption). Preparation for the attack began " +
      "as early as 2021 with testing of the vulnerability.",
    vector: "Zero-day SQL injection in MOVEit Transfer web application",
    impact:
      "2,700+ organizations affected. 95 million individuals' data " +
      "exposed. Major victims included US government agencies (DOE, " +
      "multiple state agencies), Shell, British Airways, BBC, Ernst & " +
      "Young, and numerous healthcare and financial institutions."
  },
  {
    name: "Ukraine Power Grid Attacks",
    actor: "Sandworm (BlackEnergy / Industroyer)",
    year: 2015,
    description:
      "First confirmed cyberattack to cause power outages. In December 2015, " +
      "Sandworm used BlackEnergy malware and manual SCADA manipulation to " +
      "disconnect substations at three Ukrainian power distribution companies. " +
      "In December 2016, a more sophisticated attack used Industroyer/CrashOverride " +
      "framework with native ICS protocol support.",
    vector: "Spear-phishing (2015) / network intrusion + ICS-specific malware (2016)",
    impact:
      "2015: 230,000 customers without power for 1-6 hours across three " +
      "oblasts. 2016: Kyiv substation automated attack causing blackout. " +
      "Demonstrated ICS cyberattack capability and set precedent for " +
      "infrastructure targeting."
  },
  {
    name: "Operation Aurora",
    actor: "APT17 / Elderwood Group",
    year: 2009,
    description:
      "Sophisticated espionage campaign targeting Google, Adobe, Juniper, " +
      "Rackspace, Morgan Stanley, and at least 30 other major technology " +
      "and defense companies. Used zero-day Internet Explorer vulnerability " +
      "and trojanized applications. Attack on Google targeted Chinese " +
      "dissidents' Gmail accounts.",
    vector: "Zero-day IE exploit via spear-phishing and watering holes",
    impact:
      "30+ major technology companies compromised. Google source code and " +
      "Chinese dissident Gmail account access stolen. Led to Google's " +
      "partial withdrawal from China. Revealed scale of Chinese economic " +
      "espionage operations."
  },
  {
    name: "Stuxnet",
    actor: "Equation Group / Unit 8200 (US-Israel)",
    year: 2010,
    description:
      "First known cyberweapon targeting physical infrastructure. Designed " +
      "to sabotage Iran's Natanz uranium enrichment facility by causing " +
      "centrifuges to spin at damaging speeds while reporting normal " +
      "operations. Used four zero-day exploits and stolen code signing " +
      "certificates for propagation.",
    vector: "USB propagation + network shares + four zero-day exploits",
    impact:
      "Destroyed approximately 1,000 Iranian nuclear centrifuges (of " +
      "~5,000 installed). Set back Iran's nuclear program by an estimated " +
      "1-2 years. Established precedent for nation-state cyber-physical " +
      "attacks. Proliferated after escaping Natanz network."
  },
  {
    name: "Sony Pictures Hack",
    actor: "Lazarus Group (North Korea)",
    year: 2014,
    description:
      "Destructive cyberattack against Sony Pictures Entertainment, " +
      "attributed to North Korea in retaliation for the film 'The Interview'. " +
      "Attackers exfiltrated and published confidential data including " +
      "unreleased films, executive emails, salary data, and personal " +
      "information before deploying destructive wiper malware.",
    vector: "Spear-phishing leading to network compromise and data destruction",
    impact:
      "Company-wide IT infrastructure destruction. 100TB of data stolen and " +
      "leaked. Unreleased films published. Executive emails exposed. " +
      "Estimated $35M+ in direct damages. Theatrical release of 'The " +
      "Interview' cancelled then limited. First US sanctions against a " +
      "nation-state for cyberattack."
  },
  {
    name: "MGM Resorts / Caesars Entertainment Attacks",
    actor: "Scattered Spider (ALPHV/BlackCat affiliate)",
    year: 2023,
    description:
      "Social engineering attacks against two major casino and hospitality " +
      "companies. Attackers gained initial access by calling IT help desks " +
      "and impersonating employees to obtain credentials. Caesars paid $15M " +
      "ransom. MGM refused to pay, resulting in extended outage.",
    vector: "Social engineering of IT help desk (vishing / SIM swap)",
    impact:
      "MGM: 10-day IT shutdown, $100M estimated loss, hotel operations " +
      "disrupted, slot machines offline. Caesars: $15M ransom paid, " +
      "loyalty program data exfiltrated. Highlighted vulnerability of " +
      "social engineering against enterprise help desks."
  },
  {
    name: "Change Healthcare Attack",
    actor: "ALPHV / BlackCat",
    year: 2024,
    description:
      "Ransomware attack against Change Healthcare, a subsidiary of " +
      "UnitedHealth Group that processes approximately one-third of all " +
      "US healthcare claims. Attack disrupted healthcare payment processing " +
      "nationwide for weeks. Company paid $22M ransom but data was also " +
      "held by an affiliate (RansomHub) leading to double extortion.",
    vector: "Compromised credentials on Citrix remote access (no MFA)",
    impact:
      "Disrupted healthcare payments for weeks across the US. Pharmacies " +
      "unable to process prescriptions. 100 million patient records " +
      "potentially exposed. $22M ransom paid. UHG estimated $870M+ " +
      "in attack-related costs. Largest healthcare data breach in US history."
  },
  {
    name: "Log4Shell Exploitation Wave",
    actor: "Multiple actors (APT35, Hafnium, Aquatic Panda, Conti, etc.)",
    year: 2021,
    description:
      "Mass exploitation of CVE-2021-44228, a critical remote code execution " +
      "vulnerability in Apache Log4j 2 logging library. The vulnerability " +
      "affected hundreds of millions of devices due to Log4j's ubiquity in " +
      "Java applications. State-sponsored and criminal groups raced to exploit " +
      "the flaw within hours of public disclosure.",
    vector: "Remote code execution via JNDI injection in log messages",
    impact:
      "Hundreds of millions of vulnerable devices. Exploitation observed " +
      "from nation-state actors (China, Iran, North Korea, Turkey) and " +
      "ransomware groups within 24 hours. Affected products from Apache, " +
      "VMware, Cisco, IBM, Oracle, and thousands of others. CISA described " +
      "it as one of the most serious vulnerabilities ever discovered."
  },
  {
    name: "Okta / Twilio / Cloudflare (0ktapus Campaign)",
    actor: "Scattered Spider (0ktapus)",
    year: 2022,
    description:
      "Large-scale phishing campaign targeting over 130 organizations using " +
      "Okta-themed phishing pages. Attackers sent SMS messages to employees " +
      "of target companies with links to fake Okta login pages. Successfully " +
      "compromised Twilio, used that access to target Cloudflare and Signal, " +
      "and attempted attacks against additional downstream targets.",
    vector: "SMS phishing (smishing) with fake Okta authentication pages",
    impact:
      "130+ organizations targeted. Twilio compromised (163 customers' " +
      "data exposed). Signal: 1,900 phone numbers exposed via Twilio. " +
      "Cloudflare phished but contained via hardware security keys. " +
      "Nearly 10,000 credentials harvested across campaigns."
  },
  {
    name: "Salt Typhoon Telecom Infiltration",
    actor: "Salt Typhoon",
    year: 2024,
    description:
      "Chinese state-sponsored espionage campaign that infiltrated major " +
      "US telecommunications providers including AT&T, Verizon, T-Mobile, " +
      "and others. Attackers gained access to lawful intercept (wiretap) " +
      "systems, call metadata, and potentially the communications content " +
      "of targeted government officials and political figures.",
    vector: "Exploitation of telecom infrastructure and network equipment",
    impact:
      "Major US ISPs compromised. Lawful intercept systems accessed. " +
      "Call records of government officials exposed. Prompted CISA to " +
      "issue unprecedented public guidance recommending encrypted messaging. " +
      "Described as potentially the worst telecom hack in US history."
  },
  {
    name: "Bangladesh Bank SWIFT Heist",
    actor: "Lazarus Group",
    year: 2016,
    description:
      "Cyber heist targeting Bangladesh Bank's SWIFT messaging infrastructure. " +
      "Attackers used compromised SWIFT credentials to submit 35 fraudulent " +
      "transfer requests totaling $951 million. Most transactions were blocked " +
      "by the Federal Reserve Bank of New York, but $81 million was " +
      "successfully transferred to accounts in the Philippines.",
    vector: "Compromised SWIFT terminal credentials + custom malware",
    impact:
      "$81 million stolen (of $951M attempted). Only $15M recovered. Led to " +
      "major overhaul of SWIFT Customer Security Programme. Exposed " +
      "vulnerabilities in interbank transfer systems. Connected to broader " +
      "Lazarus Group financial operations."
  },
  {
    name: "3CX Supply Chain Attack",
    actor: "Lazarus Group (Trading Technologies -> 3CX chain)",
    year: 2023,
    description:
      "Supply chain attack that compromised the 3CX desktop application, a " +
      "VoIP software used by 600,000 organizations. Notably, the attack was " +
      "itself caused by an earlier supply chain compromise of Trading " +
      "Technologies' X_TRADER software, making it a supply-chain-within-a-" +
      "supply-chain attack. The trojanized 3CX application deployed " +
      "information stealing malware.",
    vector: "Cascading supply chain compromise (Trading Technologies -> 3CX)",
    impact:
      "600,000 organizations potentially exposed. Trojanized application " +
      "deployed to subset of users. Information stealer targeting " +
      "cryptocurrency companies. First publicly documented case of one " +
      "supply chain attack leading to another."
  }
];


// ===================================================================
//  MODULE EXPORTS
// ===================================================================

module.exports = {
  THREAT_ACTORS,
  MALWARE_FAMILIES,
  IOC_PATTERNS,
  THREAT_FEEDS,
  RANSOMWARE_GROUPS,
  ATTACK_CAMPAIGNS
};
