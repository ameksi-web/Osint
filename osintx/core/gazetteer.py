"""Гео-словарь: страны, города, стеммы и распознавание местоположения в тексте.

Нужен, чтобы из реальных публичных данных (bio в Telegram, поле location на GitHub,
подписи на сайтах, номер телефона) получить ответ на вопрос «где живёт».

Распознавание работает по стеммам — началам слов в разных падежах и языках:
«в Германии», «германский», «немец», «Germany», «Berlin» → страна DE.

Никаких внешних сервисов и ключей: только офлайн-словарь, поэтому результат
воспроизводим и не «фейкуется» запросами к чужим API.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# code, русское название, английское, стеммы (регексп-фрагменты), города
COUNTRIES: list[dict] = [
    {"code": "RU", "ru": "Россия", "en": "Russia", "stems": ["росси", "россиянин", "русск", "russia", r"\brus\b", "рф"],
     "cities": [("москв", "Москва"), ("санкт-петербург", "Санкт-Петербург"), ("петербург", "Санкт-Петербург"),
                ("спб", "Санкт-Петербург"), ("новосибирск", "Новосибирск"), ("екатеринбург", "Екатеринбург"),
                ("казан", "Казань"), ("нижний новгород", "Нижний Новгород"), ("челябинск", "Челябинск"),
                ("самар", "Самара"), ("омск", "Омск"), ("ростов-на-дону", "Ростов-на-Дону"),
                ("уфа", "Уфа"), ("красноярск", "Красноярск"), ("воронеж", "Воронеж"), ("перм", "Пермь"),
                ("волгоград", "Волгоград"), ("краснодар", "Краснодар"), ("саратов", "Саратов"),
                ("тюмен", "Тюмень"), ("иркутск", "Иркутск"), ("барнаул", "Барнаул"), ("томск", "Томск"),
                ("сочи", "Сочи"), ("калининград", "Калининград"), ("владивосток", "Владивосток"),
                ("хабаровск", "Хабаровск"), ("ставропол", "Ставрополь"), ("мурманск", "Мурманск"),
                ("архангельск", "Архангельск"), ("ярославл", "Ярославль"), ("тул", "Тула")]},
    {"code": "BY", "ru": "Беларусь", "en": "Belarus", "stems": ["беларус", "белорус", "belarus", "минск"],
     "cities": [("минск", "Минск"), ("гомел", "Гомель"), ("брест", "Брест"), ("витебск", "Витебск"),
                ("гродно", "Гродно"), ("могилев", "Могилёв")]},
    {"code": "UA", "ru": "Украина", "en": "Ukraine", "stems": ["украин", "ukrain", "киев", "київ"],
     "cities": [("киев", "Киев"), ("харьков", "Харьков"), ("одесс", "Одесса"), ("днепр", "Днепр"),
                ("львов", "Львов"), ("запорож", "Запорожье"), ("винниц", "Винница"), ("полтав", "Полтава")]},
    {"code": "KZ", "ru": "Казахстан", "en": "Kazakhstan", "stems": ["казахстан", "kazakhstan", "қазақстан"],
     "cities": [("алматы", "Алматы"), ("алма-ата", "Алматы"), ("астан", "Астана"), ("нур-султан", "Астана"),
                ("шымкент", "Шымкент"), ("караганда", "Караганда"), ("актобе", "Актобе"), ("атырау", "Атырау"),
                ("павлодар", "Павлодар")]},
    {"code": "UZ", "ru": "Узбекистан", "en": "Uzbekistan", "stems": ["узбекистан", "uzbekistan"],
     "cities": [("ташкент", "Ташкент"), ("самарканд", "Самарканд"), ("бухар", "Бухара"), ("андижан", "Андижан"),
                ("ферган", "Фергана")]},
    {"code": "KG", "ru": "Киргизия", "en": "Kyrgyzstan", "stems": ["киргиз", "кыргыз", "kyrgyz"],
     "cities": [("бишкек", "Бишкек"), ("ош", "Ош")]},
    {"code": "TJ", "ru": "Таджикистан", "en": "Tajikistan", "stems": ["таджикистан", "tajikistan"],
     "cities": [("душанбе", "Душанбе"), ("худжанд", "Худжанд")]},
    {"code": "AM", "ru": "Армения", "en": "Armenia", "stems": ["армени", "armenia", "ереван"],
     "cities": [("ереван", "Ереван"), ("гюмри", "Гюмри")]},
    {"code": "GE", "ru": "Грузия", "en": "Georgia", "stems": ["грузи", "тбилиси", "грузинск"],
     "cities": [("тбилиси", "Тбилиси"), ("батуми", "Батуми"), ("кутаиси", "Кутаиси")]},
    {"code": "AZ", "ru": "Азербайджан", "en": "Azerbaijan", "stems": ["азербайджан", "azerbaijan"],
     "cities": [("баку", "Баку"), ("гяндж", "Гянджа")]},
    {"code": "MD", "ru": "Молдова", "en": "Moldova", "stems": ["молдов", "молдав", "moldova"],
     "cities": [("кишинев", "Кишинёв"), ("тираспол", "Тирасполь")]},
    {"code": "DE", "ru": "Германия", "en": "Germany", "stems": ["германи", "германск", "немец", "немк", "german", "deutschland"],
     "cities": [("берлин", "Берлин"), ("мюнхен", "Мюнхен"), ("гамбург", "Гамбург"), ("франкфурт", "Франкфурт"),
                ("кёльн", "Кёльн"), ("кельн", "Кёльн"), ("штутгарт", "Штутгарт"), ("дюссельдорф", "Дюссельдорф"),
                ("дортмунд", "Дортмунд"), ("эссен", "Эссен"), ("лейпциг", "Лейпциг"), ("дрезден", "Дрезден"),
                ("ганновер", "Ганновер"), ("нюрнберг", "Нюрнберг"), ("бремен", "Бремен"), ("бонн", "Бонн"),
                ("берлин", "Берлин"), ("мюнхен", "Мюнхен")]},
    {"code": "AT", "ru": "Австрия", "en": "Austria", "stems": ["австри", "austria", "österreich", "венск"],
     "cities": [("вен", "Вена"), ("зальцбург", "Зальцбург"), ("грац", "Грац"), ("инсбрук", "Инсбрук")]},
    {"code": "CH", "ru": "Швейцария", "en": "Switzerland", "stems": ["швейцар", "switzerland", "schweiz", "suisse"],
     "cities": [("цюрих", "Цюрих"), ("женева", "Женева"), ("базел", "Базель"), ("берн", "Берн"), ("лозанна", "Лозанна")]},
    {"code": "FR", "ru": "Франция", "en": "France", "stems": ["франц", r"\bfrance\b", "french", "француз"],
     "cities": [("париж", "Париж"), ("лион", "Лион"), ("марсел", "Марсель"), ("тулуз", "Тулуза"),
                ("ницца", "Ницца"), ("бордо", "Бордо"), ("лилль", "Лилль")]},
    {"code": "GB", "ru": "Великобритания", "en": "United Kingdom", "stems": ["великобритан", "британ", "англи", "англичан",
                                                                            "united kingdom", r"\buk\b", "london", "england", "scotland"],
     "cities": [("лондон", "Лондон"), ("манчестер", "Манчестер"), ("бирмингем", "Бирмингем"), ("лидс", "Лидс"),
                ("глaзго", "Глазго"), ("глазго", "Глазго"), ("эдинбург", "Эдинбург"), ("ливерпул", "Ливерпуль"),
                ("бристол", "Бристоль"), ("кембридж", "Кембридж"), ("оксфорд", "Оксфорд")]},
    {"code": "IE", "ru": "Ирландия", "en": "Ireland", "stems": ["ирланди", "ireland", "ирландец"],
     "cities": [("дублин", "Дублин"), ("корк", "Корк")]},
    {"code": "NL", "ru": "Нидерланды", "en": "Netherlands", "stems": ["нидерланд", "голланд", "netherlands", "dutch"],
     "cities": [("амстердам", "Амстердам"), ("роттердам", "Роттердам"), ("гааг", "Гаага"), ("утрехт", "Утрехт"),
                ("эйдховен", "Эйндховен")]},
    {"code": "BE", "ru": "Бельгия", "en": "Belgium", "stems": ["бельги", "belgium", "бельгийск"],
     "cities": [("брюссел", "Брюссель"), ("антверпен", "Антверпен"), ("гент", "Гент")]},
    {"code": "LU", "ru": "Люксембург", "en": "Luxembourg", "stems": ["люксембург", "luxembourg"], "cities": []},
    {"code": "ES", "ru": "Испания", "en": "Spain", "stems": ["испани", "spain", "испан", "españa"],
     "cities": [("мадрид", "Мадрид"), ("барселон", "Барселона"), ("валенси", "Валенсия"), ("севиль", "Севилья"),
                ("малаг", "Малага"), ("бильбао", "Бильбао")]},
    {"code": "PT", "ru": "Португалия", "en": "Portugal", "stems": ["португали", "portugal"],
     "cities": [("лиссабон", "Лиссабон"), ("порту", "Порту")]},
    {"code": "IT", "ru": "Италия", "en": "Italy", "stems": ["итали", "italy", "итальян"],
     "cities": [("рим", "Рим"), ("милан", "Милан"), ("неапол", "Неаполь"), ("турин", "Турин"),
                ("флоренци", "Флоренция"), ("венеци", "Венеция"), ("болонь", "Болонья")]},
    {"code": "GR", "ru": "Греция", "en": "Greece", "stems": ["греци", "greece", "греческ"],
     "cities": [("афин", "Афины"), ("салоник", "Салоники")]},
    {"code": "CY", "ru": "Кипр", "en": "Cyprus", "stems": ["кипр", "cyprus"],
     "cities": [("лимасол", "Лимасол"), ("никоси", "Никосия"), ("пафос", "Пафос"), ("ларнак", "Ларнака")]},
    {"code": "TR", "ru": "Турция", "en": "Turkey", "stems": ["турци", "turkey", "турецк", "türkiye"],
     "cities": [("стамбул", "Стамбул"), ("анкар", "Анкара"), ("измир", "Измир"), ("анталь", "Анталья"),
                ("алани", "Аланья")]},
    {"code": "PL", "ru": "Польша", "en": "Poland", "stems": ["польш", "poland", "польск"],
     "cities": [("варшав", "Варшава"), ("краков", "Краков"), ("гданьск", "Гданьск"), ("вроцлав", "Вроцлав"),
                ("познан", "Познань"), ("лодз", "Лодзь")]},
    {"code": "CZ", "ru": "Чехия", "en": "Czechia", "stems": ["чехи", "чешск", "czech", "прага"],
     "cities": [("праг", "Прага"), ("брно", "Брно"), ("острава", "Острава")]},
    {"code": "SK", "ru": "Словакия", "en": "Slovakia", "stems": ["словаки", "slovakia"],
     "cities": [("братислав", "Братислава"), ("кошице", "Кошице")]},
    {"code": "HU", "ru": "Венгрия", "en": "Hungary", "stems": ["венгри", "hungary", "венгерск"],
     "cities": [("будапешт", "Будапешт"), ("дебрецен", "Дебрецен")]},
    {"code": "RO", "ru": "Румыния", "en": "Romania", "stems": ["румыни", "romania"],
     "cities": [("бухарест", "Бухарест"), ("клуж", "Клуж"), ("тимишоар", "Тимишоара")]},
    {"code": "BG", "ru": "Болгария", "en": "Bulgaria", "stems": ["болгари", "bulgaria"],
     "cities": [("софи", "София"), ("варн", "Варна"), ("бургас", "Бургас"), ("пловдив", "Пловдив")]},
    {"code": "RS", "ru": "Сербия", "en": "Serbia", "stems": ["серби", "serbia"],
     "cities": [("белград", "Белград"), ("нови-сад", "Нови-Сад")]},
    {"code": "HR", "ru": "Хорватия", "en": "Croatia", "stems": ["хорвати", "croatia"],
     "cities": [("загреб", "Загреб"), ("сплит", "Сплит")]},
    {"code": "SI", "ru": "Словения", "en": "Slovenia", "stems": ["словени", "slovenia"],
     "cities": [("люблян", "Любляна")]},
    {"code": "BA", "ru": "Босния и Герцеговина", "en": "Bosnia", "stems": ["босни", "bosnia"], "cities": [("сараев", "Сараево")]},
    {"code": "ME", "ru": "Черногория", "en": "Montenegro", "stems": ["черногори", "montenegro"],
     "cities": [("подгориц", "Подгорица"), ("будв", "Будва"), ("бар", "Бар")]},
    {"code": "MK", "ru": "Северная Македония", "en": "Macedonia", "stems": ["македони", "macedonia"],
     "cities": [("скопье", "Скопье")]},
    {"code": "AL", "ru": "Албания", "en": "Albania", "stems": ["албани", "albania"], "cities": [("тиран", "Тирана")]},
    {"code": "LT", "ru": "Литва", "en": "Lithuania", "stems": ["литв", "lithuania"],
     "cities": [("вильнюс", "Вильнюс"), ("каунас", "Каунас")]},
    {"code": "LV", "ru": "Латвия", "en": "Latvia", "stems": ["латви", "latvia"],
     "cities": [("риг", "Рига"), ("даугавпилс", "Даугавпилс")]},
    {"code": "EE", "ru": "Эстония", "en": "Estonia", "stems": ["эстони", "estonia"],
     "cities": [("таллин", "Таллин"), ("тарту", "Тарту")]},
    {"code": "FI", "ru": "Финляндия", "en": "Finland", "stems": ["финлянди", "finland", "финск"],
     "cities": [("хельсинки", "Хельсинки"), ("тампере", "Тампере"), ("турку", "Турку")]},
    {"code": "SE", "ru": "Швеция", "en": "Sweden", "stems": ["швеци", "sweden", "шведск"],
     "cities": [("стокгольм", "Стокгольм"), ("гетеборг", "Гётеборг"), ("мальм", "Мальмё")]},
    {"code": "NO", "ru": "Норвегия", "en": "Norway", "stems": ["норвеги", "norway"],
     "cities": [("осло", "Осло"), ("берген", "Берген")]},
    {"code": "DK", "ru": "Дания", "en": "Denmark", "stems": ["дани", "denmark", "датск"],
     "cities": [("копенгаген", "Копенгаген"), ("орхус", "Орхус")]},
    {"code": "IS", "ru": "Исландия", "en": "Iceland", "stems": ["исланди", "iceland"], "cities": [("рейкьявик", "Рейкьявик")]},
    {"code": "US", "ru": "США", "en": "United States", "stems": ["сша", "америк", "american", r"\busa\b", "united states", "американск"],
     "cities": [("нью-йорк", "Нью-Йорк"), ("нью йорк", "Нью-Йорк"), ("new york", "Нью-Йорк"),
                ("сан-франциско", "Сан-Франциско"), ("san francisco", "Сан-Франциско"), ("лос-анджелес", "Лос-Анджелес"),
                ("лос анджелес", "Лос-Анджелес"), ("чикаго", "Чикаго"), ("чикаго", "Чикаго"), ("бостон", "Бостон"),
                ("сиэтл", "Сиэтл"), ("сиетл", "Сиэтл"), ("остin", "Остин"), ("остин", "Остин"),
                ("денвер", "Денвер"), ("майами", "Майами"), ("хьюстон", "Хьюстон"), ("филадельфи", "Филадельфия"),
                ("атлант", "Атланта"), ("даллас", "Даллас"), ("портленд", "Портленд"), ("сан-диего", "Сан-Диего"),
                ("вашингтон", "Вашингтон"), ("washington", "Вашингтон"), ("santa clara", "Санта-Клара"),
                ("palo alto", "Пало-Альто"), ("mountain view", "Маунтин-Вью")]},
    {"code": "CA", "ru": "Канада", "en": "Canada", "stems": ["канад", "canada", "канадск"],
     "cities": [("торонто", "Торонто"), ("ванкувер", "Ванкувер"), ("монреал", "Монреаль"), ("калгари", "Калгари"),
                ("оттав", "Оттава"), ("эдмонтон", "Эдмонтон")]},
    {"code": "MX", "ru": "Мексика", "en": "Mexico", "stems": ["мексик", "mexico"],
     "cities": [("мехико", "Мехико"), ("гуадалах", "Гвадалахара"), ("канкун", "Канкун")]},
    {"code": "BR", "ru": "Бразилия", "en": "Brazil", "stems": ["бразили", "brazil", "бразильск"],
     "cities": [("сан-паулу", "Сан-Паулу"), ("рио-де-жанейро", "Рио-де-Жанейро"), ("бразилиа", "Бразилиа")]},
    {"code": "AR", "ru": "Аргентина", "en": "Argentina", "stems": ["аргентин", "argentina"],
     "cities": [("буэнос-айрес", "Буэнос-Айрес"), ("кордова", "Кордова")]},
    {"code": "CL", "ru": "Чили", "en": "Chile", "stems": ["чили", r"\bchile\b", "chilean"], "cities": [("сантьяго", "Сантьяго")]},
    {"code": "CO", "ru": "Колумбия", "en": "Colombia", "stems": ["колумби", "colombia"], "cities": [("богота", "Богота")]},
    {"code": "PE", "ru": "Перу", "en": "Peru", "stems": [r"\bперу\b", r"\bperu\b"], "cities": [("лима", "Лима")]},
    {"code": "VE", "ru": "Венесуэла", "en": "Venezuela", "stems": ["венесуэл", "venezuela"], "cities": [("карак", "Каракас")]},
    {"code": "UY", "ru": "Уругвай", "en": "Uruguay", "stems": ["уругва", "uruguay"], "cities": [("монтевиде", "Монтевидео")]},
    {"code": "CN", "ru": "Китай", "en": "China", "stems": ["кита", "china", "китайск"],
     "cities": [("пекин", "Пекин"), ("шанхай", "Шанхай"), ("шэньчжэн", "Шэньчжэнь"), ("гуанчжоу", "Гуанчжоу"),
                ("чэнду", "Чэнду"), ("хункон", "Гонконг"), ("гонконг", "Гонконг"), ("ухан", "Ухань")]},
    {"code": "JP", "ru": "Япония", "en": "Japan", "stems": ["япони", "japan", "японск"],
     "cities": [("токио", "Токио"), ("осака", "Осака"), ("киото", "Киото"), ("нагоя", "Нагоя"), ("саппоро", "Саппоро")]},
    {"code": "KR", "ru": "Южная Корея", "en": "South Korea", "stems": ["коре", "korea", "корейск"],
     "cities": [("сеул", "Сеул"), ("пусан", "Пусан"), ("инчхон", "Инчхон")]},
    {"code": "KP", "ru": "КНДР", "en": "North Korea", "stems": ["кндр", "северная коре"], "cities": [("пхеньян", "Пхеньян")]},
    {"code": "IN", "ru": "Индия", "en": "India", "stems": ["инди", "india", "индийск"],
     "cities": [("дели", "Дели"), ("мумбаи", "Мумбаи"), ("бангалор", "Бангалор"), ("ченнаи", "Ченнаи"),
                ("хайдарабад", "Хайдарабад"), ("пуна", "Пуна"), ("нoida", "Ноида")]},
    {"code": "PK", "ru": "Пакистан", "en": "Pakistan", "stems": ["пакистан", "pakistan"],
     "cities": [("карачи", "Карачи"), ("лахор", "Лахор"), ("исламабад", "Исламабад")]},
    {"code": "BD", "ru": "Бангладеш", "en": "Bangladesh", "stems": ["бангладеш", "bangladesh"], "cities": [("дакк", "Дакка")]},
    {"code": "VN", "ru": "Вьетнам", "en": "Vietnam", "stems": ["вьетнам", "vietnam"],
     "cities": [("ханой", "Ханой"), ("хошимин", "Хошимин"), ("данang", "Дананг"), ("дананг", "Дананг")]},
    {"code": "TH", "ru": "Таиланд", "en": "Thailand", "stems": ["таиланд", "thailand", "тайск"],
     "cities": [("банкок", "Бангкок"), ("пхукет", "Пхукет"), ("паттай", "Паттайя"), ("чиангмай", "Чиангмай")]},
    {"code": "ID", "ru": "Индонезия", "en": "Indonesia", "stems": ["индонези", "indonesia"],
     "cities": [("джакарт", "Джакарта"), ("бали", "Бали"), ("сурабая", "Сурабая")]},
    {"code": "MY", "ru": "Малайзия", "en": "Malaysia", "stems": ["малайзи", "malaysia"], "cities": [("куала-лумпур", "Куала-Лумпур")]},
    {"code": "SG", "ru": "Сингапур", "en": "Singapore", "stems": ["сингапур", "singapore"], "cities": []},
    {"code": "PH", "ru": "Филиппины", "en": "Philippines", "stems": ["филиппин", "philippines"], "cities": [("манил", "Манила")]},
    {"code": "AE", "ru": "ОАЭ", "en": "United Arab Emirates", "stems": ["оаэ", "эмират", r"\buae\b", "dubai", "дубай"],
     "cities": [("дубай", "Дубай"), ("абу-даби", "Абу-Даби"), ("шардж", "Шарджа")]},
    {"code": "SA", "ru": "Саудовская Аравия", "en": "Saudi Arabia", "stems": ["саудовск", "saudi"],
     "cities": [("эр-рияд", "Эр-Рияд"), ("джидд", "Джидда")]},
    {"code": "QA", "ru": "Катар", "en": "Qatar", "stems": ["катар", "qatar"], "cities": [("дох", "Доха")]},
    {"code": "IL", "ru": "Израиль", "en": "Israel", "stems": ["израил", "israel", "израильск"],
     "cities": [("тель-авив", "Тель-Авив"), ("иерусалим", "Иерусалим"), ("хайф", "Хайфа"), ("нетани", "Нетания")]},
    {"code": "IR", "ru": "Иран", "en": "Iran", "stems": ["иран", "iran"], "cities": [("тегеран", "Тегеран")]},
    {"code": "IQ", "ru": "Ирак", "en": "Iraq", "stems": ["ирак", "iraq"], "cities": [("багдад", "Багдад")]},
    {"code": "EG", "ru": "Египет", "en": "Egypt", "stems": ["египет", "egypt"],
     "cities": [("каир", "Каир"), ("хургад", "Хургада"), ("шарм-эль-шейх", "Шарм-эль-Шейх"), ("александри", "Александрия")]},
    {"code": "MA", "ru": "Марокко", "en": "Morocco", "stems": ["марокко", "morocco"], "cities": [("касабланк", "Касабланка")]},
    {"code": "TN", "ru": "Тунис", "en": "Tunisia", "stems": ["тунис", "tunisia"], "cities": []},
    {"code": "ZA", "ru": "ЮАР", "en": "South Africa", "stems": ["юар", "южно-африкан", "south africa"],
     "cities": [("кейптаун", "Кейптаун"), ("йоханнесбург", "Йоханнесбург")]},
    {"code": "NG", "ru": "Нигерия", "en": "Nigeria", "stems": ["нигери", "nigeria"], "cities": [("лагос", "Лагос")]},
    {"code": "KE", "ru": "Кения", "en": "Kenya", "stems": ["кени", r"\bkenya\b"], "cities": [("найроби", "Найроби")]},
    {"code": "AU", "ru": "Австралия", "en": "Australia", "stems": ["австрали", "australia"],
     "cities": [("сидней", "Сидней"), ("мельбурн", "Мельбурн"), ("брисбен", "Брисбен"), ("перт", "Перт")]},
    {"code": "NZ", "ru": "Новая Зеландия", "en": "New Zealand", "stems": ["нов(ая|ой) зеланд", "new zealand"],
     "cities": [("окленд", "Окленд"), ("веллингтон", "Веллингтон")]},
    {"code": "TW", "ru": "Тайвань", "en": "Taiwan", "stems": ["тайван", "taiwan"], "cities": [("тайбэй", "Тайбэй")]},
    {"code": "HK", "ru": "Гонконг", "en": "Hong Kong", "stems": ["гонконг", "hong kong"], "cities": []},
    {"code": "MN", "ru": "Монголия", "en": "Mongolia", "stems": ["монголи", "mongolia"], "cities": [("улан-батор", "Улан-Батор")]},
    {"code": "NP", "ru": "Непал", "en": "Nepal", "stems": ["непал", "nepal"], "cities": [("катманду", "Катманду")]},
    {"code": "LK", "ru": "Шри-Ланка", "en": "Sri Lanka", "stems": ["шри-ланк", "sri lanka"], "cities": [("коломбо", "Коломбо")]},
    {"code": "CU", "ru": "Куба", "en": "Cuba", "stems": [r"\bкуба\b", r"\bкубе\b", "cuba", "cuban"], "cities": [("гаван", "Гавана")]},
    {"code": "PR", "ru": "Пуэрто-Рико", "en": "Puerto Rico", "stems": ["пуэрто-рико", "puerto rico"], "cities": []},
    {"code": "BY", "ru": "Беларусь", "en": "Belarus", "stems": ["белорус"], "cities": []},
]

# телефоны: код страны → страна (для номеров без срабатывания библиотеки)
PHONE_PREFIX = {
    "7": "RU", "375": "BY", "380": "UA", "77": "KZ", "998": "UZ", "996": "KG", "992": "TJ",
    "374": "AM", "995": "GE", "994": "AZ", "373": "MD", "49": "DE", "43": "AT", "41": "CH",
    "33": "FR", "44": "GB", "353": "IE", "31": "NL", "32": "BE", "34": "ES", "351": "PT",
    "39": "IT", "30": "GR", "357": "CY", "90": "TR", "48": "PL", "420": "CZ", "421": "SK",
    "36": "HU", "40": "RO", "359": "BG", "381": "RS", "385": "HR", "386": "SI", "382": "ME",
    "370": "LT", "371": "LV", "372": "EE", "358": "FI", "46": "SE", "47": "NO", "45": "DK",
    "354": "IS", "1": "US", "52": "MX", "55": "BR", "54": "AR", "56": "CL", "57": "CO",
    "86": "CN", "81": "JP", "82": "KR", "91": "IN", "92": "PK", "880": "BD", "84": "VN",
    "66": "TH", "62": "ID", "60": "MY", "65": "SG", "63": "PH", "971": "AE", "966": "SA",
    "974": "QA", "972": "IL", "98": "IR", "964": "IQ", "20": "EG", "27": "ZA", "234": "NG",
    "254": "KE", "61": "AU", "64": "NZ", "886": "TW", "852": "HK", "976": "MN", "977": "NP",
    "94": "LK", "53": "CU",
}

_BY_CODE = {c["code"]: c for c in COUNTRIES}
_BY_RU = {}
for _c in COUNTRIES:
    _BY_RU.setdefault(_c["ru"], _c)

# города: стемма → (страна, город)
CITY_INDEX: dict[str, tuple[str, str]] = {}
for _c in COUNTRIES:
    for _stem, _city in _c["cities"]:
        CITY_INDEX.setdefault(_stem, (_c["code"], _city))

# Английские названия городов (профили на GitHub/GitLab/Steam чаще английские).
# Формат: "как пишут в профиле" → (код страны, русское название города)
CITY_EN: dict[str, tuple[str, str]] = {
    "moscow": ("RU", "Москва"), "saint petersburg": ("RU", "Санкт-Петербург"), "st petersburg": ("RU", "Санкт-Петербург"),
    "novosibirsk": ("RU", "Новосибирск"), "yekaterinburg": ("RU", "Екатеринбург"), "kazan": ("RU", "Казань"),
    "spb": ("RU", "Санкт-Петербург"), "minsk": ("BY", "Минск"), "kyiv": ("UA", "Киев"), "kiev": ("UA", "Киев"),
    "kharkiv": ("UA", "Харьков"), "odesa": ("UA", "Одесса"), "lviv": ("UA", "Львов"),
    "almaty": ("KZ", "Алматы"), "astana": ("KZ", "Астана"), "nur-sultan": ("KZ", "Астана"),
    "tashkent": ("UZ", "Ташкент"), "bishkek": ("KG", "Бишкек"), "yerevan": ("AM", "Ереван"),
    "tbilisi": ("GE", "Тбилиси"), "baku": ("AZ", "Баку"), "chisinau": ("MD", "Кишинёв"),
    "berlin": ("DE", "Берлин"), "munich": ("DE", "Мюнхен"), "munchen": ("DE", "Мюнхен"), "hamburg": ("DE", "Гамбург"),
    "frankfurt": ("DE", "Франкфурт"), "cologne": ("DE", "Кёльн"), "koln": ("DE", "Кёльн"),
    "stuttgart": ("DE", "Штутгарт"), "dusseldorf": ("DE", "Дюссельдорф"), "dusseldorf ": ("DE", "Дюссельдорф"),
    "dortmund": ("DE", "Дортмунд"), "leipzig": ("DE", "Лейпциг"), "dresden": ("DE", "Дрезден"),
    "hannover": ("DE", "Ганновер"), "hanover": ("DE", "Ганновер"), "nuremberg": ("DE", "Нюрнберг"),
    "bremen": ("DE", "Бремен"), "bonn": ("DE", "Бонн"), "aachen": ("DE", "Ахен"), "karlsruhe": ("DE", "Карлсруэ"),
    "vienna": ("AT", "Вена"), "wien": ("AT", "Вена"), "salzburg": ("AT", "Зальцбург"), "graz": ("AT", "Грац"),
    "zurich": ("CH", "Цюрих"), "geneva": ("CH", "Женева"), "basel": ("CH", "Базель"), "bern": ("CH", "Берн"),
    "lausanne": ("CH", "Лозанна"), "paris": ("FR", "Париж"), "lyon": ("FR", "Лион"), "marseille": ("FR", "Марсель"),
    "toulouse": ("FR", "Тулуза"), "nice": ("FR", "Ницца"), "bordeaux": ("FR", "Бордо"), "lille": ("FR", "Лилль"),
    "london": ("GB", "Лондон"), "manchester": ("GB", "Манчестер"), "birmingham": ("GB", "Бирмингем"),
    "leeds": ("GB", "Лидс"), "glasgow": ("GB", "Глазго"), "edinburgh": ("GB", "Эдинбург"),
    "liverpool": ("GB", "Ливерпуль"), "bristol": ("GB", "Бристоль"), "cambridge": ("GB", "Кембридж"),
    "oxford": ("GB", "Оксфорд"), "dublin": ("IE", "Дублин"), "cork": ("IE", "Корк"),
    "amsterdam": ("NL", "Амстердам"), "rotterdam": ("NL", "Роттердам"), "the hague": ("NL", "Гаага"),
    "utrecht": ("NL", "Утрехт"), "eindhoven": ("NL", "Эйндховен"), "brussels": ("BE", "Брюссель"),
    "antwerp": ("BE", "Антверпен"), "ghent": ("BE", "Гент"), "madrid": ("ES", "Мадрид"),
    "barcelona": ("ES", "Барселона"), "valencia": ("ES", "Валенсия"), "seville": ("ES", "Севилья"),
    "malaga": ("ES", "Малага"), "bilbao": ("ES", "Бильбао"), "lisbon": ("PT", "Лиссабон"), "porto": ("PT", "Порту"),
    "rome": ("IT", "Рим"), "milan": ("IT", "Милан"), "naples": ("IT", "Неаполь"), "turin": ("IT", "Турин"),
    "florence": ("IT", "Флоренция"), "venice": ("IT", "Венеция"), "bologna": ("IT", "Болонья"),
    "athens": ("GR", "Афины"), "thessaloniki": ("GR", "Салоники"), "limassol": ("CY", "Лимасол"),
    "nicosia": ("CY", "Никосия"), "paphos": ("CY", "Пафос"), "larnaca": ("CY", "Ларнака"),
    "istanbul": ("TR", "Стамбул"), "ankara": ("TR", "Анкара"), "izmir": ("TR", "Измир"),
    "antalya": ("TR", "Анталья"), "alanya": ("TR", "Аланья"), "warsaw": ("PL", "Варшава"),
    "krakow": ("PL", "Краков"), "gdansk": ("PL", "Гданьск"), "wroclaw": ("PL", "Вроцлав"),
    "poznan": ("PL", "Познань"), "lodz": ("PL", "Лодзь"), "prague": ("CZ", "Прага"), "brno": ("CZ", "Брно"),
    "ostrava": ("CZ", "Острава"), "bratislava": ("SK", "Братислава"), "kosice": ("SK", "Кошице"),
    "budapest": ("HU", "Будапешт"), "bucharest": ("RO", "Бухарест"), "cluj": ("RO", "Клуж"),
    "sofia": ("BG", "София"), "varna": ("BG", "Варна"), "burgas": ("BG", "Бургас"), "plovdiv": ("BG", "Пловдив"),
    "belgrade": ("RS", "Белград"), "novi sad": ("RS", "Нови-Сад"), "zagreb": ("HR", "Загреб"), "split": ("HR", "Сплит"),
    "ljubljana": ("SI", "Любляна"), "sarajevo": ("BA", "Сараево"), "podgorica": ("ME", "Подгорица"),
    "budva": ("ME", "Будва"), "skopje": ("MK", "Скопье"), "tirana": ("AL", "Тирана"),
    "vilnius": ("LT", "Вильнюс"), "kaunas": ("LT", "Каунас"), "riga": ("LV", "Рига"), "daugavpils": ("LV", "Даугавпилс"),
    "tallinn": ("EE", "Таллин"), "tartu": ("EE", "Тарту"), "helsinki": ("FI", "Хельсинки"),
    "tampere": ("FI", "Тампере"), "turku": ("FI", "Турку"), "stockholm": ("SE", "Стокгольм"),
    "gothenburg": ("SE", "Гётеборг"), "malmo": ("SE", "Мальмё"), "oslo": ("NO", "Осло"), "bergen": ("NO", "Берген"),
    "copenhagen": ("DK", "Копенгаген"), "aarhus": ("DK", "Орхус"), "reykjavik": ("IS", "Рейкьявик"),
    "new york": ("US", "Нью-Йорк"), "nyc": ("US", "Нью-Йорк"), "san francisco": ("US", "Сан-Франциско"),
    "los angeles": ("US", "Лос-Анджелес"), "chicago": ("US", "Чикаго"), "boston": ("US", "Бостон"),
    "seattle": ("US", "Сиэтл"), "austin": ("US", "Остин"), "denver": ("US", "Денвер"), "miami": ("US", "Майами"),
    "houston": ("US", "Хьюстон"), "philadelphia": ("US", "Филадельфия"), "atlanta": ("US", "Атланта"),
    "dallas": ("US", "Даллас"), "portland": ("US", "Портленд"), "san diego": ("US", "Сан-Диего"),
    "washington": ("US", "Вашингтон"), "santa clara": ("US", "Санта-Клара"), "palo alto": ("US", "Пало-Альто"),
    "mountain view": ("US", "Маунтин-Вью"), "san jose": ("US", "Сан-Хосе"), "detroit": ("US", "Детройт"),
    "minneapolis": ("US", "Миннеаполис"), "phoenix": ("US", "Финикс"), "nashville": ("US", "Нашвилл"),
    "boulder": ("US", "Боулдер"), "raleigh": ("US", "Роли"), "toronto": ("CA", "Торонто"),
    "vancouver": ("CA", "Ванкувер"), "montreal": ("CA", "Монреаль"), "calgary": ("CA", "Калгари"),
    "ottawa": ("CA", "Оттава"), "edmonton": ("CA", "Эдмонтон"), "mexico city": ("MX", "Мехико"),
    "guadalajara": ("MX", "Гвадалахара"), "cancun": ("MX", "Канкун"), "sao paulo": ("BR", "Сан-Паулу"),
    "rio de janeiro": ("BR", "Рио-де-Жанейро"), "brasilia": ("BR", "Бразилиа"), "buenos aires": ("AR", "Буэнос-Айрес"),
    "santiago": ("CL", "Сантьяго"), "bogota": ("CO", "Богота"), "lima": ("PE", "Лима"),
    "beijing": ("CN", "Пекин"), "shanghai": ("CN", "Шанхай"), "shenzhen": ("CN", "Шэньчжэнь"),
    "guangzhou": ("CN", "Гуанчжоу"), "chengdu": ("CN", "Чэнду"), "hong kong": ("HK", "Гонконг"),
    "wuhan": ("CN", "Ухань"), "tokyo": ("JP", "Токио"), "osaka": ("JP", "Осака"), "kyoto": ("JP", "Киото"),
    "nagoya": ("JP", "Нагоя"), "sapporo": ("JP", "Саппоро"), "seoul": ("KR", "Сеул"), "busan": ("KR", "Пусан"),
    "incheon": ("KR", "Инчхон"), "pyongyang": ("KP", "Пхеньян"), "delhi": ("IN", "Дели"), "new delhi": ("IN", "Дели"),
    "mumbai": ("IN", "Мумбаи"), "bangalore": ("IN", "Бангалор"), "bengaluru": ("IN", "Бангалор"),
    "chennai": ("IN", "Ченнаи"), "hyderabad": ("IN", "Хайдарабад"), "pune": ("IN", "Пуна"), "noida": ("IN", "Ноида"),
    "karachi": ("PK", "Карачи"), "lahore": ("PK", "Лахор"), "islamabad": ("PK", "Исламабад"),
    "dhaka": ("BD", "Дакка"), "hanoi": ("VN", "Ханой"), "ho chi minh": ("VN", "Хошимин"), "danang": ("VN", "Дананг"),
    "bangkok": ("TH", "Бангкок"), "phuket": ("TH", "Пхукет"), "pattaya": ("TH", "Паттайя"),
    "chiang mai": ("TH", "Чиангмай"), "jakarta": ("ID", "Джакарта"), "bali": ("ID", "Бали"),
    "kuala lumpur": ("MY", "Куала-Лумпур"), "manila": ("PH", "Манила"), "dubai": ("AE", "Дубай"),
    "abu dhabi": ("AE", "Абу-Даби"), "sharjah": ("AE", "Шарджа"), "riyadh": ("SA", "Эр-Рияд"),
    "jeddah": ("SA", "Джидда"), "doha": ("QA", "Доха"), "tel aviv": ("IL", "Тель-Авив"),
    "jerusalem": ("IL", "Иерусалим"), "haifa": ("IL", "Хайфа"), "netanya": ("IL", "Нетания"),
    "tehran": ("IR", "Тегеран"), "baghdad": ("IQ", "Багдад"), "cairo": ("EG", "Каир"),
    "hurghada": ("EG", "Хургада"), "sharm el sheikh": ("EG", "Шарм-эль-Шейх"), "alexandria": ("EG", "Александрия"),
    "casablanca": ("MA", "Касабланка"), "cape town": ("ZA", "Кейптаун"), "johannesburg": ("ZA", "Йоханнесбург"),
    "lagos": ("NG", "Лагос"), "nairobi": ("KE", "Найроби"), "sydney": ("AU", "Сидней"), "melbourne": ("AU", "Мельбурн"),
    "brisbane": ("AU", "Брисбен"), "perth": ("AU", "Перт"), "auckland": ("NZ", "Окленд"),
    "wellington": ("NZ", "Веллингтон"), "taipei": ("TW", "Тайбэй"), "ulaanbaatar": ("MN", "Улан-Батор"),
    "kathmandu": ("NP", "Катманду"), "colombo": ("LK", "Коломбо"), "havana": ("CU", "Гавана"),
}

# Штаты/провинции: «Portland, OR», «Toronto, ON», «Sydney, NSW» — уточняют страну.
REGIONS: dict[str, str] = {
    # США (двухбуквенные коды штатов)
    "al": "US", "ak": "US", "az": "US", "ar": "US", "ca": "US", "co": "US", "ct": "US", "de": "US",
    "fl": "US", "ga": "US", "hi": "US", "id": "US", "il": "US", "in": "US", "ia": "US", "ks": "US",
    "ky": "US", "la": "US", "me": "US", "md": "US", "ma": "US", "mi": "US", "mn": "US", "ms": "US",
    "mo": "US", "mt": "US", "ne": "US", "nv": "US", "nh": "US", "nj": "US", "nm": "US", "ny": "US",
    "nc": "US", "nd": "US", "oh": "US", "ok": "US", "or": "US", "pa": "US", "ri": "US", "sc": "US",
    "sd": "US", "tn": "US", "tx": "US", "ut": "US", "vt": "US", "va": "US", "wa": "US", "wv": "US",
    "wi": "US", "wy": "US", "dc": "US",
    # Канада
    "on": "CA", "qc": "CA", "bc": "CA", "ab": "CA", "mb": "CA", "sk": "CA", "ns": "CA", "nb": "CA",
    "nl": "CA", "pe": "CA",
    # Австралия
    "nsw": "AU", "vic": "AU", "qld": "AU", "sa": "AU", "tas": "AU", "act": "AU",
}

REGION_NAMES = {
    "indiana": "US", "georgia state": "US",
    "california": "US", "texas": "US", "new york state": "US", "florida": "US", "oregon": "US",
    "washington state": "US", "illinois": "US", "massachusetts": "US", "colorado": "US",
    "ontario": "CA", "quebec": "CA", "british columbia": "CA", "alberta": "CA",
    "bavaria": "DE", "bayern": "DE", "nrw": "DE", "north rhine-westphalia": "DE", "hesse": "DE",
    "baden-wurttemberg": "DE", "saxony": "DE", "lower saxony": "DE",
    "england": "GB", "scotland": "GB", "wales": "GB", "northern ireland": "GB",
    "catalonia": "ES", "andalusia": "ES", "lombardy": "IT", "tuscany": "IT",
}

REGION_RE = re.compile(r"[,·|/]\s*([A-Za-z]{2,3})\b")

# английские названия городов подключаем к индексу городов
for _stem, _pair in CITY_EN.items():
    CITY_INDEX.setdefault(_stem, _pair)


def country_from_region(text: str) -> str:
    """Страна по штату/провинции: «Portland, OR» → US, «Bavaria» → DE."""
    if not text:
        return ""
    low = text.lower()
    for name, code in REGION_NAMES.items():
        if re.search(rf"\b{re.escape(name)}\b", low):
            return code
    for found in REGION_RE.finditer(text):
        token = found.group(1)
        if token.isupper() and token.lower() in REGIONS:
            return REGIONS[token.lower()]
    return ""


# тексты, которые не являются местоположением
BLACKLIST = {"remote", "удалённ", "удаленн", "world", "worldwide", "глобальн", "anywhere",
             "everywhere", "весь мир", "планет", "earth", "internet", "интернет"}


@dataclass
class Match:
    """Найденное местоположение."""
    code: str
    country: str
    city: str = ""
    matched: str = ""
    confidence: str = "medium"
    extra: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.city}, {self.country}" if self.city else self.country


def country_name(code: str) -> str:
    item = _BY_CODE.get((code or "").upper())
    return item["ru"] if item else (code or "").upper()


def country_item(code: str) -> dict | None:
    return _BY_CODE.get((code or "").upper())


def all_countries() -> list[dict]:
    return COUNTRIES


def cities_of(code: str) -> list[str]:
    item = _BY_CODE.get((code or "").upper())
    return [city for _stem, city in (item or {}).get("cities", [])]


def _compile(stem: str) -> re.Pattern[str]:
    """Стемма → регексп с границами слова (учитывает падежи русских слов)."""
    if stem.startswith(r"\b") or stem.endswith(r"\b") or stem.startswith("("):
        return re.compile(stem, re.IGNORECASE)
    if stem.endswith(tuple("бвгджзклмнпрстфхцчшщ")) and len(stem) > 4:
        return re.compile(rf"\b{re.escape(stem)}[а-яё]*", re.IGNORECASE)
    if re.fullmatch(r"[a-zA-Z]+", stem):
        return re.compile(rf"\b{re.escape(stem)}\w*", re.IGNORECASE)
    return re.compile(rf"\b{re.escape(stem)}[а-яёA-Za-z]*", re.IGNORECASE)


_COMPILED = [(c, [_compile(s) for s in c["stems"]]) for c in COUNTRIES]
_CITY_COMPILED = [(_compile(stem), city, code) for stem, (code, city) in CITY_INDEX.items()]


def find_country(text: str) -> list[Match]:
    """Все упоминания стран в тексте (без дублей по коду)."""
    if not text:
        return []
    out: list[Match] = []
    seen: set[str] = set()
    low = text.lower()
    for item, patterns in _COMPILED:
        if item["code"] in seen:
            continue
        for pattern in patterns:
            found = pattern.search(low)
            if found and not any(b in found.group(0).lower() for b in BLACKLIST):
                out.append(Match(code=item["code"], country=item["ru"], matched=found.group(0),
                                 confidence="medium"))
                seen.add(item["code"])
                break
    return out


def find_city(text: str) -> list[Match]:
    """Все упоминания городов (с определением страны)."""
    if not text:
        return []
    out: list[Match] = []
    seen: set[tuple[str, str]] = set()
    low = text.lower()
    for pattern, city, code in _CITY_COMPILED:
        found = pattern.search(low)
        if not found:
            continue
        key = (code, city)
        if key in seen:
            continue
        seen.add(key)
        out.append(Match(code=code, country=country_name(code), city=city, matched=found.group(0),
                         confidence="high"))
    return out


def find_location(text: str) -> list[Match]:
    """Страны + города из текста; сначала города (они точнее)."""
    if not text:
        return []
    matches = find_city(text) + find_country(text)
    with_city = {m.code for m in matches if m.city}
    out: list[Match] = []
    seen: set[str] = set()
    for m in matches:
        if not m.city and m.code in with_city:
            continue          # страну уже подтвердил конкретный город — не дублируем «страну вообще»
        key = f"{m.code}:{m.city}"
        if key in seen:
            continue
        seen.add(key)
        out.append(m)
    return out


def country_from_phone(e164: str, region_hint: str = "") -> str:
    """Страна по номеру телефона: сначала phonenumbers, потом префикс вручную."""
    digits = "".join(ch for ch in (e164 or "") if ch.isdigit())
    if not digits:
        return ""
    try:  # основной путь — библиотека
        import phonenumbers

        number = phonenumbers.parse(e164 if e164.startswith("+") else f"+{digits}", None)
        code = phonenumbers.region_code_for_number(number)
        if code:
            return code.upper()
    except Exception:
        pass
    for length in (3, 2, 1):  # аккуратный fallback: сначала длинные коды
        prefix = digits[:length]
        if prefix in PHONE_PREFIX:
            return PHONE_PREFIX[prefix]
    return region_hint.upper()
