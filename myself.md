שרשרת התקיפה שאני ממליץ עליה
01 — Reconnaissance
        ↓
02 — RDP Brute Force
        ↓
03 — Discovery as Jsmith
        ↓
04 — Credential / Account Discovery
        ↓
05 — Privilege Escalation
        ↓
06 — Persistence
        ↓
07 — Suspicious Execution
        ↓
08 — SOC Detection & Investigation

הסיפור שאנחנו רוצים שה-SOC יראה הוא:

התוקף התחיל מבחוץ → השיג גישה ל־Jsmith → ביצע Discovery → הבין מה ההרשאות והמבנה של הסביבה → השיג/ניצל הרשאות גבוהות יותר → יצר Persistence → ביצע פעילות נוספת עם ההרשאות החדשות.

קודם כל — המשתמשים בפרויקט

כרגע יש לך רק:

Jsmith

על מכונת הקורבן.

אני ממליץ לא ליצור עכשיו עשרות משתמשים. מספיקים לנו 3–4 משתמשים.

1. MYLAB\Jsmith

סוג: Domain User
מיקום: מחשב הקורבן
הרשאות: רגילות

זה המשתמש שנפגע ב־RDP Brute Force.

הוא יהיה ה־Initial Access Account.

Attacker
   ↓
RDP Brute Force
   ↓
MYLAB\Jsmith
   ↓
Victim-01
2. MYLAB\Administrator

סוג: Domain Administrator
מיקום: AD / DC-01
הרשאות: גבוהות מאוד

זה יהיה החשבון שאנחנו רוצים שהתוקף ינסה להגיע אליו בהמשך.

חשוב: לא צריך לפרוץ אליו בפועל בשביל שהפרויקט יעבוד. אפשר להשתמש בו כיעד/חשבון privileged ולבנות את שלב ה־Privilege Escalation בצורה מבוקרת.

3. MYLAB\svc_backup

סוג: Service Account
מיקום: Domain
הרשאות: מוגבלות אך גבוהות יותר מ־Jsmith, בהתאם למה שנגדיר

המשתמש הזה נותן לנו משהו חשוב:

לא כל חשבון מעניין ב־AD הוא Administrator.

כך במהלך Discovery התוקף יכול למצוא חשבון Service ולהבין שיש לו ערך פוטנציאלי.

4. משתמש נוסף — אופציונלי

לדוגמה:

MYLAB\Bob

סוג: Domain User
הרשאות: רגילות

לא חובה כרגע.

אם הפרויקט מתחיל להיות גדול מדי — אל תיצור אותו.

המכונות

הייתי בונה את ה-Lab בצורה הזאת:

                 ┌──────────────────┐
                 │   ATTACKER       │
                 │   Kali Linux     │
                 │ 192.168.10.133   │
                 └────────┬─────────┘
                          │
                          │
              ┌───────────┴───────────┐
              │       LAB NETWORK      │
              └───────────┬───────────┘
                          │
             ┌────────────┴────────────┐
             │                         │
      ┌──────▼──────┐           ┌──────▼──────┐
      │  Victim-01  │           │    DC-01     │
      │ Windows     │           │ Windows      │
      │             │           │ Server / AD  │
      │ Jsmith      │           │              │
      └─────────────┘           └──────────────┘

ואם יש לך עוד Windows machine:

             ┌──────────────┐
             │  Victim-02   │
             │ Windows      │
             │              │
             │ Bob          │
             └──────────────┘

אבל Victim-02 לא הכרחית בשלב הזה.

04 — Credential / Account Discovery

אחרי שהתוקף התחבר כ־Jsmith, הוא כבר ביצע את ה־Discovery שנתת לי:

whoami
whoami /groups
hostname
systeminfo
ipconfig /all
net user /domain
net group /domain
nltest /dsgetdc:MYLAB
arp -a
net view /domain
net view \\DC-01

עכשיו אנחנו רוצים שהתוקף יעבד את המידע.

לדוגמה:

Jsmith
 ↓
Who am I?
 ↓
What groups am I in?
 ↓
What accounts exist?
 ↓
What privileged groups exist?
 ↓
What machines exist?
 ↓
Where is DC-01?

וזה נותן לנו מעבר טבעי:

Discovery → Credential/Privilege Discovery

במקום סתם לקפוץ לטכניקה אחרת.

05 — Privilege Escalation

כאן הייתי עושה את זה בצורה מבוקרת ובטוחה בתוך ה-Lab, ולא מכניס לפרויקט Credential Dumping אמיתי.

המטרה היא פשוט ליצור מצב שבו:

Jsmith
   ↓
Normal User
   ↓
Suspicious privilege-related activity
   ↓
Higher privileges

מה שמעניין אותנו מבחינת Defender הוא לא רק "האם הצלחנו להיות Admin", אלא:

מה ה-SOC רואה?

לדוגמה:

User: Jsmith


Process:
    suspicious_process.exe


Parent:
    powershell.exe


Integrity Level:
    High


User Context:
    MYLAB\Jsmith

או פעילות שגורמת לשינוי בהרשאות/קבוצות.

זה נותן לנו Investigation אמיתי:

למה משתמש רגיל ביצע פעילות שהובילה ל־High Integrity / administrative context?

06 — Persistence

אחרי שהתוקף השיג הרשאות גבוהות יותר, אנחנו רוצים שהוא לא יצטרך לבצע שוב את כל שרשרת ה־RDP Brute Force.

לכן נוסיף Persistence.

אני ממליץ לפרויקט שלך על:

Scheduled Task

הסיפור:

Jsmith
   ↓
Privilege Escalation
   ↓
Create Scheduled Task
   ↓
Task executes a benign test action
   ↓
Persistence

ה־Payload עצמו יכול להיות פעולה harmless לחלוטין, למשל יצירת קובץ סימון בתוך תיקיית Lab.

לדוגמה רעיונית:

C:\SOC-Lab\persistence-test.txt

כך אנחנו לא צריכים Malware אמיתי.

אבל Defender עדיין יכול לראות את הפעילות סביב:

schtasks.exe
      ↓
Task creation
      ↓
Task execution
      ↓
Child process

וזה מעולה ל־SOC.

07 — Suspicious Execution

עכשיו נוסיף עוד שלב קטן.

ה־Scheduled Task מפעיל פעולה מבוקרת שמייצרת Telemetry.

למשל:

Task Scheduler
      ↓
powershell.exe
      ↓
Create SOC-Lab marker

עכשיו יש לנו Process Tree מעניין:

svchost.exe
    └── Task Scheduler
          └── powershell.exe
                └── test action

ומבחינת Tier 1 Analyst אפשר לשאול:

מי יצר את ה־Scheduled Task?
מי הפעיל אותו?
מתי?
מה היה ה־Parent Process?
איזה Command Line היה?
איזה User Context?
האם PowerShell היה מעורב?
האם נוצר קובץ?
האם הייתה פעילות Network?
האם הפעילות קשורה ל־Jsmith?
האם הייתה Privilege Escalation לפני כן?
