/**
 * We use our own specialized module operating on raw bits and bytes as much as possible
 * since the bip39 crane decrases speed by a factor of 35
 */
use sha2::{Digest, Sha256};

// https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
const WORDS: [&[u8]; 2048] = [
    b"abandon",
    b"ability",
    b"able",
    b"about",
    b"above",
    b"absent",
    b"absorb",
    b"abstract",
    b"absurd",
    b"abuse",
    b"access",
    b"accident",
    b"account",
    b"accuse",
    b"achieve",
    b"acid",
    b"acoustic",
    b"acquire",
    b"across",
    b"act",
    b"action",
    b"actor",
    b"actress",
    b"actual",
    b"adapt",
    b"add",
    b"addict",
    b"address",
    b"adjust",
    b"admit",
    b"adult",
    b"advance",
    b"advice",
    b"aerobic",
    b"affair",
    b"afford",
    b"afraid",
    b"again",
    b"age",
    b"agent",
    b"agree",
    b"ahead",
    b"aim",
    b"air",
    b"airport",
    b"aisle",
    b"alarm",
    b"album",
    b"alcohol",
    b"alert",
    b"alien",
    b"all",
    b"alley",
    b"allow",
    b"almost",
    b"alone",
    b"alpha",
    b"already",
    b"also",
    b"alter",
    b"always",
    b"amateur",
    b"amazing",
    b"among",
    b"amount",
    b"amused",
    b"analyst",
    b"anchor",
    b"ancient",
    b"anger",
    b"angle",
    b"angry",
    b"animal",
    b"ankle",
    b"announce",
    b"annual",
    b"another",
    b"answer",
    b"antenna",
    b"antique",
    b"anxiety",
    b"any",
    b"apart",
    b"apology",
    b"appear",
    b"apple",
    b"approve",
    b"april",
    b"arch",
    b"arctic",
    b"area",
    b"arena",
    b"argue",
    b"arm",
    b"armed",
    b"armor",
    b"army",
    b"around",
    b"arrange",
    b"arrest",
    b"arrive",
    b"arrow",
    b"art",
    b"artefact",
    b"artist",
    b"artwork",
    b"ask",
    b"aspect",
    b"assault",
    b"asset",
    b"assist",
    b"assume",
    b"asthma",
    b"athlete",
    b"atom",
    b"attack",
    b"attend",
    b"attitude",
    b"attract",
    b"auction",
    b"audit",
    b"august",
    b"aunt",
    b"author",
    b"auto",
    b"autumn",
    b"average",
    b"avocado",
    b"avoid",
    b"awake",
    b"aware",
    b"away",
    b"awesome",
    b"awful",
    b"awkward",
    b"axis",
    b"baby",
    b"bachelor",
    b"bacon",
    b"badge",
    b"bag",
    b"balance",
    b"balcony",
    b"ball",
    b"bamboo",
    b"banana",
    b"banner",
    b"bar",
    b"barely",
    b"bargain",
    b"barrel",
    b"base",
    b"basic",
    b"basket",
    b"battle",
    b"beach",
    b"bean",
    b"beauty",
    b"because",
    b"become",
    b"beef",
    b"before",
    b"begin",
    b"behave",
    b"behind",
    b"believe",
    b"below",
    b"belt",
    b"bench",
    b"benefit",
    b"best",
    b"betray",
    b"better",
    b"between",
    b"beyond",
    b"bicycle",
    b"bid",
    b"bike",
    b"bind",
    b"biology",
    b"bird",
    b"birth",
    b"bitter",
    b"black",
    b"blade",
    b"blame",
    b"blanket",
    b"blast",
    b"bleak",
    b"bless",
    b"blind",
    b"blood",
    b"blossom",
    b"blouse",
    b"blue",
    b"blur",
    b"blush",
    b"board",
    b"boat",
    b"body",
    b"boil",
    b"bomb",
    b"bone",
    b"bonus",
    b"book",
    b"boost",
    b"border",
    b"boring",
    b"borrow",
    b"boss",
    b"bottom",
    b"bounce",
    b"box",
    b"boy",
    b"bracket",
    b"brain",
    b"brand",
    b"brass",
    b"brave",
    b"bread",
    b"breeze",
    b"brick",
    b"bridge",
    b"brief",
    b"bright",
    b"bring",
    b"brisk",
    b"broccoli",
    b"broken",
    b"bronze",
    b"broom",
    b"brother",
    b"brown",
    b"brush",
    b"bubble",
    b"buddy",
    b"budget",
    b"buffalo",
    b"build",
    b"bulb",
    b"bulk",
    b"bullet",
    b"bundle",
    b"bunker",
    b"burden",
    b"burger",
    b"burst",
    b"bus",
    b"business",
    b"busy",
    b"butter",
    b"buyer",
    b"buzz",
    b"cabbage",
    b"cabin",
    b"cable",
    b"cactus",
    b"cage",
    b"cake",
    b"call",
    b"calm",
    b"camera",
    b"camp",
    b"can",
    b"canal",
    b"cancel",
    b"candy",
    b"cannon",
    b"canoe",
    b"canvas",
    b"canyon",
    b"capable",
    b"capital",
    b"captain",
    b"car",
    b"carbon",
    b"card",
    b"cargo",
    b"carpet",
    b"carry",
    b"cart",
    b"case",
    b"cash",
    b"casino",
    b"castle",
    b"casual",
    b"cat",
    b"catalog",
    b"catch",
    b"category",
    b"cattle",
    b"caught",
    b"cause",
    b"caution",
    b"cave",
    b"ceiling",
    b"celery",
    b"cement",
    b"census",
    b"century",
    b"cereal",
    b"certain",
    b"chair",
    b"chalk",
    b"champion",
    b"change",
    b"chaos",
    b"chapter",
    b"charge",
    b"chase",
    b"chat",
    b"cheap",
    b"check",
    b"cheese",
    b"chef",
    b"cherry",
    b"chest",
    b"chicken",
    b"chief",
    b"child",
    b"chimney",
    b"choice",
    b"choose",
    b"chronic",
    b"chuckle",
    b"chunk",
    b"churn",
    b"cigar",
    b"cinnamon",
    b"circle",
    b"citizen",
    b"city",
    b"civil",
    b"claim",
    b"clap",
    b"clarify",
    b"claw",
    b"clay",
    b"clean",
    b"clerk",
    b"clever",
    b"click",
    b"client",
    b"cliff",
    b"climb",
    b"clinic",
    b"clip",
    b"clock",
    b"clog",
    b"close",
    b"cloth",
    b"cloud",
    b"clown",
    b"club",
    b"clump",
    b"cluster",
    b"clutch",
    b"coach",
    b"coast",
    b"coconut",
    b"code",
    b"coffee",
    b"coil",
    b"coin",
    b"collect",
    b"color",
    b"column",
    b"combine",
    b"come",
    b"comfort",
    b"comic",
    b"common",
    b"company",
    b"concert",
    b"conduct",
    b"confirm",
    b"congress",
    b"connect",
    b"consider",
    b"control",
    b"convince",
    b"cook",
    b"cool",
    b"copper",
    b"copy",
    b"coral",
    b"core",
    b"corn",
    b"correct",
    b"cost",
    b"cotton",
    b"couch",
    b"country",
    b"couple",
    b"course",
    b"cousin",
    b"cover",
    b"coyote",
    b"crack",
    b"cradle",
    b"craft",
    b"cram",
    b"crane",
    b"crash",
    b"crater",
    b"crawl",
    b"crazy",
    b"cream",
    b"credit",
    b"creek",
    b"crew",
    b"cricket",
    b"crime",
    b"crisp",
    b"critic",
    b"crop",
    b"cross",
    b"crouch",
    b"crowd",
    b"crucial",
    b"cruel",
    b"cruise",
    b"crumble",
    b"crunch",
    b"crush",
    b"cry",
    b"crystal",
    b"cube",
    b"culture",
    b"cup",
    b"cupboard",
    b"curious",
    b"current",
    b"curtain",
    b"curve",
    b"cushion",
    b"custom",
    b"cute",
    b"cycle",
    b"dad",
    b"damage",
    b"damp",
    b"dance",
    b"danger",
    b"daring",
    b"dash",
    b"daughter",
    b"dawn",
    b"day",
    b"deal",
    b"debate",
    b"debris",
    b"decade",
    b"december",
    b"decide",
    b"decline",
    b"decorate",
    b"decrease",
    b"deer",
    b"defense",
    b"define",
    b"defy",
    b"degree",
    b"delay",
    b"deliver",
    b"demand",
    b"demise",
    b"denial",
    b"dentist",
    b"deny",
    b"depart",
    b"depend",
    b"deposit",
    b"depth",
    b"deputy",
    b"derive",
    b"describe",
    b"desert",
    b"design",
    b"desk",
    b"despair",
    b"destroy",
    b"detail",
    b"detect",
    b"develop",
    b"device",
    b"devote",
    b"diagram",
    b"dial",
    b"diamond",
    b"diary",
    b"dice",
    b"diesel",
    b"diet",
    b"differ",
    b"digital",
    b"dignity",
    b"dilemma",
    b"dinner",
    b"dinosaur",
    b"direct",
    b"dirt",
    b"disagree",
    b"discover",
    b"disease",
    b"dish",
    b"dismiss",
    b"disorder",
    b"display",
    b"distance",
    b"divert",
    b"divide",
    b"divorce",
    b"dizzy",
    b"doctor",
    b"document",
    b"dog",
    b"doll",
    b"dolphin",
    b"domain",
    b"donate",
    b"donkey",
    b"donor",
    b"door",
    b"dose",
    b"double",
    b"dove",
    b"draft",
    b"dragon",
    b"drama",
    b"drastic",
    b"draw",
    b"dream",
    b"dress",
    b"drift",
    b"drill",
    b"drink",
    b"drip",
    b"drive",
    b"drop",
    b"drum",
    b"dry",
    b"duck",
    b"dumb",
    b"dune",
    b"during",
    b"dust",
    b"dutch",
    b"duty",
    b"dwarf",
    b"dynamic",
    b"eager",
    b"eagle",
    b"early",
    b"earn",
    b"earth",
    b"easily",
    b"east",
    b"easy",
    b"echo",
    b"ecology",
    b"economy",
    b"edge",
    b"edit",
    b"educate",
    b"effort",
    b"egg",
    b"eight",
    b"either",
    b"elbow",
    b"elder",
    b"electric",
    b"elegant",
    b"element",
    b"elephant",
    b"elevator",
    b"elite",
    b"else",
    b"embark",
    b"embody",
    b"embrace",
    b"emerge",
    b"emotion",
    b"employ",
    b"empower",
    b"empty",
    b"enable",
    b"enact",
    b"end",
    b"endless",
    b"endorse",
    b"enemy",
    b"energy",
    b"enforce",
    b"engage",
    b"engine",
    b"enhance",
    b"enjoy",
    b"enlist",
    b"enough",
    b"enrich",
    b"enroll",
    b"ensure",
    b"enter",
    b"entire",
    b"entry",
    b"envelope",
    b"episode",
    b"equal",
    b"equip",
    b"era",
    b"erase",
    b"erode",
    b"erosion",
    b"error",
    b"erupt",
    b"escape",
    b"essay",
    b"essence",
    b"estate",
    b"eternal",
    b"ethics",
    b"evidence",
    b"evil",
    b"evoke",
    b"evolve",
    b"exact",
    b"example",
    b"excess",
    b"exchange",
    b"excite",
    b"exclude",
    b"excuse",
    b"execute",
    b"exercise",
    b"exhaust",
    b"exhibit",
    b"exile",
    b"exist",
    b"exit",
    b"exotic",
    b"expand",
    b"expect",
    b"expire",
    b"explain",
    b"expose",
    b"express",
    b"extend",
    b"extra",
    b"eye",
    b"eyebrow",
    b"fabric",
    b"face",
    b"faculty",
    b"fade",
    b"faint",
    b"faith",
    b"fall",
    b"false",
    b"fame",
    b"family",
    b"famous",
    b"fan",
    b"fancy",
    b"fantasy",
    b"farm",
    b"fashion",
    b"fat",
    b"fatal",
    b"father",
    b"fatigue",
    b"fault",
    b"favorite",
    b"feature",
    b"february",
    b"federal",
    b"fee",
    b"feed",
    b"feel",
    b"female",
    b"fence",
    b"festival",
    b"fetch",
    b"fever",
    b"few",
    b"fiber",
    b"fiction",
    b"field",
    b"figure",
    b"file",
    b"film",
    b"filter",
    b"final",
    b"find",
    b"fine",
    b"finger",
    b"finish",
    b"fire",
    b"firm",
    b"first",
    b"fiscal",
    b"fish",
    b"fit",
    b"fitness",
    b"fix",
    b"flag",
    b"flame",
    b"flash",
    b"flat",
    b"flavor",
    b"flee",
    b"flight",
    b"flip",
    b"float",
    b"flock",
    b"floor",
    b"flower",
    b"fluid",
    b"flush",
    b"fly",
    b"foam",
    b"focus",
    b"fog",
    b"foil",
    b"fold",
    b"follow",
    b"food",
    b"foot",
    b"force",
    b"forest",
    b"forget",
    b"fork",
    b"fortune",
    b"forum",
    b"forward",
    b"fossil",
    b"foster",
    b"found",
    b"fox",
    b"fragile",
    b"frame",
    b"frequent",
    b"fresh",
    b"friend",
    b"fringe",
    b"frog",
    b"front",
    b"frost",
    b"frown",
    b"frozen",
    b"fruit",
    b"fuel",
    b"fun",
    b"funny",
    b"furnace",
    b"fury",
    b"future",
    b"gadget",
    b"gain",
    b"galaxy",
    b"gallery",
    b"game",
    b"gap",
    b"garage",
    b"garbage",
    b"garden",
    b"garlic",
    b"garment",
    b"gas",
    b"gasp",
    b"gate",
    b"gather",
    b"gauge",
    b"gaze",
    b"general",
    b"genius",
    b"genre",
    b"gentle",
    b"genuine",
    b"gesture",
    b"ghost",
    b"giant",
    b"gift",
    b"giggle",
    b"ginger",
    b"giraffe",
    b"girl",
    b"give",
    b"glad",
    b"glance",
    b"glare",
    b"glass",
    b"glide",
    b"glimpse",
    b"globe",
    b"gloom",
    b"glory",
    b"glove",
    b"glow",
    b"glue",
    b"goat",
    b"goddess",
    b"gold",
    b"good",
    b"goose",
    b"gorilla",
    b"gospel",
    b"gossip",
    b"govern",
    b"gown",
    b"grab",
    b"grace",
    b"grain",
    b"grant",
    b"grape",
    b"grass",
    b"gravity",
    b"great",
    b"green",
    b"grid",
    b"grief",
    b"grit",
    b"grocery",
    b"group",
    b"grow",
    b"grunt",
    b"guard",
    b"guess",
    b"guide",
    b"guilt",
    b"guitar",
    b"gun",
    b"gym",
    b"habit",
    b"hair",
    b"half",
    b"hammer",
    b"hamster",
    b"hand",
    b"happy",
    b"harbor",
    b"hard",
    b"harsh",
    b"harvest",
    b"hat",
    b"have",
    b"hawk",
    b"hazard",
    b"head",
    b"health",
    b"heart",
    b"heavy",
    b"hedgehog",
    b"height",
    b"hello",
    b"helmet",
    b"help",
    b"hen",
    b"hero",
    b"hidden",
    b"high",
    b"hill",
    b"hint",
    b"hip",
    b"hire",
    b"history",
    b"hobby",
    b"hockey",
    b"hold",
    b"hole",
    b"holiday",
    b"hollow",
    b"home",
    b"honey",
    b"hood",
    b"hope",
    b"horn",
    b"horror",
    b"horse",
    b"hospital",
    b"host",
    b"hotel",
    b"hour",
    b"hover",
    b"hub",
    b"huge",
    b"human",
    b"humble",
    b"humor",
    b"hundred",
    b"hungry",
    b"hunt",
    b"hurdle",
    b"hurry",
    b"hurt",
    b"husband",
    b"hybrid",
    b"ice",
    b"icon",
    b"idea",
    b"identify",
    b"idle",
    b"ignore",
    b"ill",
    b"illegal",
    b"illness",
    b"image",
    b"imitate",
    b"immense",
    b"immune",
    b"impact",
    b"impose",
    b"improve",
    b"impulse",
    b"inch",
    b"include",
    b"income",
    b"increase",
    b"index",
    b"indicate",
    b"indoor",
    b"industry",
    b"infant",
    b"inflict",
    b"inform",
    b"inhale",
    b"inherit",
    b"initial",
    b"inject",
    b"injury",
    b"inmate",
    b"inner",
    b"innocent",
    b"input",
    b"inquiry",
    b"insane",
    b"insect",
    b"inside",
    b"inspire",
    b"install",
    b"intact",
    b"interest",
    b"into",
    b"invest",
    b"invite",
    b"involve",
    b"iron",
    b"island",
    b"isolate",
    b"issue",
    b"item",
    b"ivory",
    b"jacket",
    b"jaguar",
    b"jar",
    b"jazz",
    b"jealous",
    b"jeans",
    b"jelly",
    b"jewel",
    b"job",
    b"join",
    b"joke",
    b"journey",
    b"joy",
    b"judge",
    b"juice",
    b"jump",
    b"jungle",
    b"junior",
    b"junk",
    b"just",
    b"kangaroo",
    b"keen",
    b"keep",
    b"ketchup",
    b"key",
    b"kick",
    b"kid",
    b"kidney",
    b"kind",
    b"kingdom",
    b"kiss",
    b"kit",
    b"kitchen",
    b"kite",
    b"kitten",
    b"kiwi",
    b"knee",
    b"knife",
    b"knock",
    b"know",
    b"lab",
    b"label",
    b"labor",
    b"ladder",
    b"lady",
    b"lake",
    b"lamp",
    b"language",
    b"laptop",
    b"large",
    b"later",
    b"latin",
    b"laugh",
    b"laundry",
    b"lava",
    b"law",
    b"lawn",
    b"lawsuit",
    b"layer",
    b"lazy",
    b"leader",
    b"leaf",
    b"learn",
    b"leave",
    b"lecture",
    b"left",
    b"leg",
    b"legal",
    b"legend",
    b"leisure",
    b"lemon",
    b"lend",
    b"length",
    b"lens",
    b"leopard",
    b"lesson",
    b"letter",
    b"level",
    b"liar",
    b"liberty",
    b"library",
    b"license",
    b"life",
    b"lift",
    b"light",
    b"like",
    b"limb",
    b"limit",
    b"link",
    b"lion",
    b"liquid",
    b"list",
    b"little",
    b"live",
    b"lizard",
    b"load",
    b"loan",
    b"lobster",
    b"local",
    b"lock",
    b"logic",
    b"lonely",
    b"long",
    b"loop",
    b"lottery",
    b"loud",
    b"lounge",
    b"love",
    b"loyal",
    b"lucky",
    b"luggage",
    b"lumber",
    b"lunar",
    b"lunch",
    b"luxury",
    b"lyrics",
    b"machine",
    b"mad",
    b"magic",
    b"magnet",
    b"maid",
    b"mail",
    b"main",
    b"major",
    b"make",
    b"mammal",
    b"man",
    b"manage",
    b"mandate",
    b"mango",
    b"mansion",
    b"manual",
    b"maple",
    b"marble",
    b"march",
    b"margin",
    b"marine",
    b"market",
    b"marriage",
    b"mask",
    b"mass",
    b"master",
    b"match",
    b"material",
    b"math",
    b"matrix",
    b"matter",
    b"maximum",
    b"maze",
    b"meadow",
    b"mean",
    b"measure",
    b"meat",
    b"mechanic",
    b"medal",
    b"media",
    b"melody",
    b"melt",
    b"member",
    b"memory",
    b"mention",
    b"menu",
    b"mercy",
    b"merge",
    b"merit",
    b"merry",
    b"mesh",
    b"message",
    b"metal",
    b"method",
    b"middle",
    b"midnight",
    b"milk",
    b"million",
    b"mimic",
    b"mind",
    b"minimum",
    b"minor",
    b"minute",
    b"miracle",
    b"mirror",
    b"misery",
    b"miss",
    b"mistake",
    b"mix",
    b"mixed",
    b"mixture",
    b"mobile",
    b"model",
    b"modify",
    b"mom",
    b"moment",
    b"monitor",
    b"monkey",
    b"monster",
    b"month",
    b"moon",
    b"moral",
    b"more",
    b"morning",
    b"mosquito",
    b"mother",
    b"motion",
    b"motor",
    b"mountain",
    b"mouse",
    b"move",
    b"movie",
    b"much",
    b"muffin",
    b"mule",
    b"multiply",
    b"muscle",
    b"museum",
    b"mushroom",
    b"music",
    b"must",
    b"mutual",
    b"myself",
    b"mystery",
    b"myth",
    b"naive",
    b"name",
    b"napkin",
    b"narrow",
    b"nasty",
    b"nation",
    b"nature",
    b"near",
    b"neck",
    b"need",
    b"negative",
    b"neglect",
    b"neither",
    b"nephew",
    b"nerve",
    b"nest",
    b"net",
    b"network",
    b"neutral",
    b"never",
    b"news",
    b"next",
    b"nice",
    b"night",
    b"noble",
    b"noise",
    b"nominee",
    b"noodle",
    b"normal",
    b"north",
    b"nose",
    b"notable",
    b"note",
    b"nothing",
    b"notice",
    b"novel",
    b"now",
    b"nuclear",
    b"number",
    b"nurse",
    b"nut",
    b"oak",
    b"obey",
    b"object",
    b"oblige",
    b"obscure",
    b"observe",
    b"obtain",
    b"obvious",
    b"occur",
    b"ocean",
    b"october",
    b"odor",
    b"off",
    b"offer",
    b"office",
    b"often",
    b"oil",
    b"okay",
    b"old",
    b"olive",
    b"olympic",
    b"omit",
    b"once",
    b"one",
    b"onion",
    b"online",
    b"only",
    b"open",
    b"opera",
    b"opinion",
    b"oppose",
    b"option",
    b"orange",
    b"orbit",
    b"orchard",
    b"order",
    b"ordinary",
    b"organ",
    b"orient",
    b"original",
    b"orphan",
    b"ostrich",
    b"other",
    b"outdoor",
    b"outer",
    b"output",
    b"outside",
    b"oval",
    b"oven",
    b"over",
    b"own",
    b"owner",
    b"oxygen",
    b"oyster",
    b"ozone",
    b"pact",
    b"paddle",
    b"page",
    b"pair",
    b"palace",
    b"palm",
    b"panda",
    b"panel",
    b"panic",
    b"panther",
    b"paper",
    b"parade",
    b"parent",
    b"park",
    b"parrot",
    b"party",
    b"pass",
    b"patch",
    b"path",
    b"patient",
    b"patrol",
    b"pattern",
    b"pause",
    b"pave",
    b"payment",
    b"peace",
    b"peanut",
    b"pear",
    b"peasant",
    b"pelican",
    b"pen",
    b"penalty",
    b"pencil",
    b"people",
    b"pepper",
    b"perfect",
    b"permit",
    b"person",
    b"pet",
    b"phone",
    b"photo",
    b"phrase",
    b"physical",
    b"piano",
    b"picnic",
    b"picture",
    b"piece",
    b"pig",
    b"pigeon",
    b"pill",
    b"pilot",
    b"pink",
    b"pioneer",
    b"pipe",
    b"pistol",
    b"pitch",
    b"pizza",
    b"place",
    b"planet",
    b"plastic",
    b"plate",
    b"play",
    b"please",
    b"pledge",
    b"pluck",
    b"plug",
    b"plunge",
    b"poem",
    b"poet",
    b"point",
    b"polar",
    b"pole",
    b"police",
    b"pond",
    b"pony",
    b"pool",
    b"popular",
    b"portion",
    b"position",
    b"possible",
    b"post",
    b"potato",
    b"pottery",
    b"poverty",
    b"powder",
    b"power",
    b"practice",
    b"praise",
    b"predict",
    b"prefer",
    b"prepare",
    b"present",
    b"pretty",
    b"prevent",
    b"price",
    b"pride",
    b"primary",
    b"print",
    b"priority",
    b"prison",
    b"private",
    b"prize",
    b"problem",
    b"process",
    b"produce",
    b"profit",
    b"program",
    b"project",
    b"promote",
    b"proof",
    b"property",
    b"prosper",
    b"protect",
    b"proud",
    b"provide",
    b"public",
    b"pudding",
    b"pull",
    b"pulp",
    b"pulse",
    b"pumpkin",
    b"punch",
    b"pupil",
    b"puppy",
    b"purchase",
    b"purity",
    b"purpose",
    b"purse",
    b"push",
    b"put",
    b"puzzle",
    b"pyramid",
    b"quality",
    b"quantum",
    b"quarter",
    b"question",
    b"quick",
    b"quit",
    b"quiz",
    b"quote",
    b"rabbit",
    b"raccoon",
    b"race",
    b"rack",
    b"radar",
    b"radio",
    b"rail",
    b"rain",
    b"raise",
    b"rally",
    b"ramp",
    b"ranch",
    b"random",
    b"range",
    b"rapid",
    b"rare",
    b"rate",
    b"rather",
    b"raven",
    b"raw",
    b"razor",
    b"ready",
    b"real",
    b"reason",
    b"rebel",
    b"rebuild",
    b"recall",
    b"receive",
    b"recipe",
    b"record",
    b"recycle",
    b"reduce",
    b"reflect",
    b"reform",
    b"refuse",
    b"region",
    b"regret",
    b"regular",
    b"reject",
    b"relax",
    b"release",
    b"relief",
    b"rely",
    b"remain",
    b"remember",
    b"remind",
    b"remove",
    b"render",
    b"renew",
    b"rent",
    b"reopen",
    b"repair",
    b"repeat",
    b"replace",
    b"report",
    b"require",
    b"rescue",
    b"resemble",
    b"resist",
    b"resource",
    b"response",
    b"result",
    b"retire",
    b"retreat",
    b"return",
    b"reunion",
    b"reveal",
    b"review",
    b"reward",
    b"rhythm",
    b"rib",
    b"ribbon",
    b"rice",
    b"rich",
    b"ride",
    b"ridge",
    b"rifle",
    b"right",
    b"rigid",
    b"ring",
    b"riot",
    b"ripple",
    b"risk",
    b"ritual",
    b"rival",
    b"river",
    b"road",
    b"roast",
    b"robot",
    b"robust",
    b"rocket",
    b"romance",
    b"roof",
    b"rookie",
    b"room",
    b"rose",
    b"rotate",
    b"rough",
    b"round",
    b"route",
    b"royal",
    b"rubber",
    b"rude",
    b"rug",
    b"rule",
    b"run",
    b"runway",
    b"rural",
    b"sad",
    b"saddle",
    b"sadness",
    b"safe",
    b"sail",
    b"salad",
    b"salmon",
    b"salon",
    b"salt",
    b"salute",
    b"same",
    b"sample",
    b"sand",
    b"satisfy",
    b"satoshi",
    b"sauce",
    b"sausage",
    b"save",
    b"say",
    b"scale",
    b"scan",
    b"scare",
    b"scatter",
    b"scene",
    b"scheme",
    b"school",
    b"science",
    b"scissors",
    b"scorpion",
    b"scout",
    b"scrap",
    b"screen",
    b"script",
    b"scrub",
    b"sea",
    b"search",
    b"season",
    b"seat",
    b"second",
    b"secret",
    b"section",
    b"security",
    b"seed",
    b"seek",
    b"segment",
    b"select",
    b"sell",
    b"seminar",
    b"senior",
    b"sense",
    b"sentence",
    b"series",
    b"service",
    b"session",
    b"settle",
    b"setup",
    b"seven",
    b"shadow",
    b"shaft",
    b"shallow",
    b"share",
    b"shed",
    b"shell",
    b"sheriff",
    b"shield",
    b"shift",
    b"shine",
    b"ship",
    b"shiver",
    b"shock",
    b"shoe",
    b"shoot",
    b"shop",
    b"short",
    b"shoulder",
    b"shove",
    b"shrimp",
    b"shrug",
    b"shuffle",
    b"shy",
    b"sibling",
    b"sick",
    b"side",
    b"siege",
    b"sight",
    b"sign",
    b"silent",
    b"silk",
    b"silly",
    b"silver",
    b"similar",
    b"simple",
    b"since",
    b"sing",
    b"siren",
    b"sister",
    b"situate",
    b"six",
    b"size",
    b"skate",
    b"sketch",
    b"ski",
    b"skill",
    b"skin",
    b"skirt",
    b"skull",
    b"slab",
    b"slam",
    b"sleep",
    b"slender",
    b"slice",
    b"slide",
    b"slight",
    b"slim",
    b"slogan",
    b"slot",
    b"slow",
    b"slush",
    b"small",
    b"smart",
    b"smile",
    b"smoke",
    b"smooth",
    b"snack",
    b"snake",
    b"snap",
    b"sniff",
    b"snow",
    b"soap",
    b"soccer",
    b"social",
    b"sock",
    b"soda",
    b"soft",
    b"solar",
    b"soldier",
    b"solid",
    b"solution",
    b"solve",
    b"someone",
    b"song",
    b"soon",
    b"sorry",
    b"sort",
    b"soul",
    b"sound",
    b"soup",
    b"source",
    b"south",
    b"space",
    b"spare",
    b"spatial",
    b"spawn",
    b"speak",
    b"special",
    b"speed",
    b"spell",
    b"spend",
    b"sphere",
    b"spice",
    b"spider",
    b"spike",
    b"spin",
    b"spirit",
    b"split",
    b"spoil",
    b"sponsor",
    b"spoon",
    b"sport",
    b"spot",
    b"spray",
    b"spread",
    b"spring",
    b"spy",
    b"square",
    b"squeeze",
    b"squirrel",
    b"stable",
    b"stadium",
    b"staff",
    b"stage",
    b"stairs",
    b"stamp",
    b"stand",
    b"start",
    b"state",
    b"stay",
    b"steak",
    b"steel",
    b"stem",
    b"step",
    b"stereo",
    b"stick",
    b"still",
    b"sting",
    b"stock",
    b"stomach",
    b"stone",
    b"stool",
    b"story",
    b"stove",
    b"strategy",
    b"street",
    b"strike",
    b"strong",
    b"struggle",
    b"student",
    b"stuff",
    b"stumble",
    b"style",
    b"subject",
    b"submit",
    b"subway",
    b"success",
    b"such",
    b"sudden",
    b"suffer",
    b"sugar",
    b"suggest",
    b"suit",
    b"summer",
    b"sun",
    b"sunny",
    b"sunset",
    b"super",
    b"supply",
    b"supreme",
    b"sure",
    b"surface",
    b"surge",
    b"surprise",
    b"surround",
    b"survey",
    b"suspect",
    b"sustain",
    b"swallow",
    b"swamp",
    b"swap",
    b"swarm",
    b"swear",
    b"sweet",
    b"swift",
    b"swim",
    b"swing",
    b"switch",
    b"sword",
    b"symbol",
    b"symptom",
    b"syrup",
    b"system",
    b"table",
    b"tackle",
    b"tag",
    b"tail",
    b"talent",
    b"talk",
    b"tank",
    b"tape",
    b"target",
    b"task",
    b"taste",
    b"tattoo",
    b"taxi",
    b"teach",
    b"team",
    b"tell",
    b"ten",
    b"tenant",
    b"tennis",
    b"tent",
    b"term",
    b"test",
    b"text",
    b"thank",
    b"that",
    b"theme",
    b"then",
    b"theory",
    b"there",
    b"they",
    b"thing",
    b"this",
    b"thought",
    b"three",
    b"thrive",
    b"throw",
    b"thumb",
    b"thunder",
    b"ticket",
    b"tide",
    b"tiger",
    b"tilt",
    b"timber",
    b"time",
    b"tiny",
    b"tip",
    b"tired",
    b"tissue",
    b"title",
    b"toast",
    b"tobacco",
    b"today",
    b"toddler",
    b"toe",
    b"together",
    b"toilet",
    b"token",
    b"tomato",
    b"tomorrow",
    b"tone",
    b"tongue",
    b"tonight",
    b"tool",
    b"tooth",
    b"top",
    b"topic",
    b"topple",
    b"torch",
    b"tornado",
    b"tortoise",
    b"toss",
    b"total",
    b"tourist",
    b"toward",
    b"tower",
    b"town",
    b"toy",
    b"track",
    b"trade",
    b"traffic",
    b"tragic",
    b"train",
    b"transfer",
    b"trap",
    b"trash",
    b"travel",
    b"tray",
    b"treat",
    b"tree",
    b"trend",
    b"trial",
    b"tribe",
    b"trick",
    b"trigger",
    b"trim",
    b"trip",
    b"trophy",
    b"trouble",
    b"truck",
    b"true",
    b"truly",
    b"trumpet",
    b"trust",
    b"truth",
    b"try",
    b"tube",
    b"tuition",
    b"tumble",
    b"tuna",
    b"tunnel",
    b"turkey",
    b"turn",
    b"turtle",
    b"twelve",
    b"twenty",
    b"twice",
    b"twin",
    b"twist",
    b"two",
    b"type",
    b"typical",
    b"ugly",
    b"umbrella",
    b"unable",
    b"unaware",
    b"uncle",
    b"uncover",
    b"under",
    b"undo",
    b"unfair",
    b"unfold",
    b"unhappy",
    b"uniform",
    b"unique",
    b"unit",
    b"universe",
    b"unknown",
    b"unlock",
    b"until",
    b"unusual",
    b"unveil",
    b"update",
    b"upgrade",
    b"uphold",
    b"upon",
    b"upper",
    b"upset",
    b"urban",
    b"urge",
    b"usage",
    b"use",
    b"used",
    b"useful",
    b"useless",
    b"usual",
    b"utility",
    b"vacant",
    b"vacuum",
    b"vague",
    b"valid",
    b"valley",
    b"valve",
    b"van",
    b"vanish",
    b"vapor",
    b"various",
    b"vast",
    b"vault",
    b"vehicle",
    b"velvet",
    b"vendor",
    b"venture",
    b"venue",
    b"verb",
    b"verify",
    b"version",
    b"very",
    b"vessel",
    b"veteran",
    b"viable",
    b"vibrant",
    b"vicious",
    b"victory",
    b"video",
    b"view",
    b"village",
    b"vintage",
    b"violin",
    b"virtual",
    b"virus",
    b"visa",
    b"visit",
    b"visual",
    b"vital",
    b"vivid",
    b"vocal",
    b"voice",
    b"void",
    b"volcano",
    b"volume",
    b"vote",
    b"voyage",
    b"wage",
    b"wagon",
    b"wait",
    b"walk",
    b"wall",
    b"walnut",
    b"want",
    b"warfare",
    b"warm",
    b"warrior",
    b"wash",
    b"wasp",
    b"waste",
    b"water",
    b"wave",
    b"way",
    b"wealth",
    b"weapon",
    b"wear",
    b"weasel",
    b"weather",
    b"web",
    b"wedding",
    b"weekend",
    b"weird",
    b"welcome",
    b"west",
    b"wet",
    b"whale",
    b"what",
    b"wheat",
    b"wheel",
    b"when",
    b"where",
    b"whip",
    b"whisper",
    b"wide",
    b"width",
    b"wife",
    b"wild",
    b"will",
    b"win",
    b"window",
    b"wine",
    b"wing",
    b"wink",
    b"winner",
    b"winter",
    b"wire",
    b"wisdom",
    b"wise",
    b"wish",
    b"witness",
    b"wolf",
    b"woman",
    b"wonder",
    b"wood",
    b"wool",
    b"word",
    b"work",
    b"world",
    b"worry",
    b"worth",
    b"wrap",
    b"wreck",
    b"wrestle",
    b"wrist",
    b"write",
    b"wrong",
    b"yard",
    b"year",
    b"yellow",
    b"you",
    b"young",
    b"youth",
    b"zebra",
    b"zero",
    b"zone",
    b"zoo",
];

/**
 *
 * eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeecccc
 * |---0--||---1--||---2--||---3--||---4--||---5--||---6--||---7--||---8--||---9--||--10--||--11--||--12--||--13--||--14--||--15--||--16--|
 * (----0----)(----1----)(----2----)(----3----)(----4----)(----5----)(----6----)(----7----)(----8----)(----9----)(----10---)(----11---)
 *
 */
pub fn entropy_to_mnemonic(entropy: &[u8; 16]) -> Vec<u8> {
    let checksum = Sha256::digest(entropy);

    let entropy_single: u128 = 0u128
        | (entropy[0] as u128) << (128 - 1 * 8)
        | (entropy[1] as u128) << (128 - 2 * 8)
        | (entropy[2] as u128) << (128 - 3 * 8)
        | (entropy[3] as u128) << (128 - 4 * 8)
        | (entropy[4] as u128) << (128 - 5 * 8)
        | (entropy[5] as u128) << (128 - 6 * 8)
        | (entropy[6] as u128) << (128 - 7 * 8)
        | (entropy[7] as u128) << (128 - 8 * 8)
        | (entropy[8] as u128) << (128 - 9 * 8)
        | (entropy[9] as u128) << (128 - 10 * 8)
        | (entropy[10] as u128) << (128 - 11 * 8)
        | (entropy[11] as u128) << (128 - 12 * 8)
        | (entropy[12] as u128) << (128 - 13 * 8)
        | (entropy[13] as u128) << (128 - 14 * 8)
        | (entropy[14] as u128) << (128 - 15 * 8)
        | (entropy[15] as u128) << (128 - 16 * 8);

    let mut word_index: [usize; 12] = [0; 12];
    for i in 0..11 {
        word_index[i] = ((entropy_single >> 128 - (i + 1) * 11) & 0x7ff) as usize;
    }
    // low 7 bit of entropy_single and top 4 bit of checksum
    word_index[11] = (((entropy_single & 0x7f) << 4) as usize) | ((checksum[0] >> 4) as usize);

    let out: Vec<u8> = [
        WORDS[word_index[0]],
        b" ",
        WORDS[word_index[1]],
        b" ",
        WORDS[word_index[2]],
        b" ",
        WORDS[word_index[3]],
        b" ",
        WORDS[word_index[4]],
        b" ",
        WORDS[word_index[5]],
        b" ",
        WORDS[word_index[6]],
        b" ",
        WORDS[word_index[7]],
        b" ",
        WORDS[word_index[8]],
        b" ",
        WORDS[word_index[9]],
        b" ",
        WORDS[word_index[10]],
        b" ",
        WORDS[word_index[11]],
    ]
    .concat();

    return out;
}

#[cfg(test)]
mod tests {
    // importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_entropy_to_bytes() {
        // https://github.com/iov-one/iov-core/blob/v0.9.1/packages/iov-crypto/src/bip39.spec.ts#L13
        let mut entropy = [0u8; 16];

        hex::decode_to_slice("00000000000000000000000000000000", &mut entropy).unwrap();
        assert_eq!(entropy_to_mnemonic(&entropy).as_slice(), b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" as &[u8]);

        hex::decode_to_slice("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", &mut entropy).unwrap();
        assert_eq!(
            entropy_to_mnemonic(&entropy).as_slice(),
            b"legal winner thank year wave sausage worth useful legal winner thank yellow"
                as &[u8]
        );

        hex::decode_to_slice("80808080808080808080808080808080", &mut entropy).unwrap();
        assert_eq!(
            entropy_to_mnemonic(&entropy).as_slice(),
            b"letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
                as &[u8]
        );

        hex::decode_to_slice("ffffffffffffffffffffffffffffffff", &mut entropy).unwrap();
        assert_eq!(
            entropy_to_mnemonic(&entropy).as_slice(),
            b"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong" as &[u8]
        );
    }
}