import angr
import claripy
import sys

# نام فایل اجرایی
binary_name = "./vuln"

# آدرس هایی که باید پیدا و از آنها اجتناب کنیم (فرضی، باید از روی Ghidra/IDA Pro استخراج شوند)
# فرض کنید آدرس بلوک "Welcome!" (موفقیت) این است:
FIND_ADDR = 0x401234
# فرض کنید آدرس بلوک "denied.!!!!!" (شکست) این است:
AVOID_ADDR = 0x401242 

print(f"[*] در حال بارگذاری باینری: {binary_name}")
# ایجاد یک شیء پروژه (Project) از باینری
proj = angr.Project(binary_name)

# تعریف طول پسورد به صورت نمادین (فرض می‌کنیم پسورد حداکثر 20 کاراکتر است)
# claripy.BVS یک BitVectorSymbolic می‌سازد که نشان‌دهنده ورودی نمادین است.
# 20 * 8 = 160 بیت
SYMBOLIC_PASSWORD_LEN = 20
password_symbol = claripy.BVS("password", SYMBOLIC_PASSWORD_LEN * 8)

# تعریف حالت اولیه (Initial State)
# این چالش یک پسورد را از طریق آرگومان خط فرمان (argv[1]) دریافت می‌کند.
# state = proj.factory.entry_state(args=[binary_name, password_symbol]) 
# * اگر برنامه پسورد را از استاندارد ورودی (stdin) بخواند (مانند scanf/read)، از دستور زیر استفاده می‌کنیم:
# state = proj.factory.entry_state(stdin=angr.storage.file.SimFileStream(name='stdin', content=password_symbol))

# با توجه به پیغام `Usage: %s <password>`، برنامه از آرگومان خط فرمان استفاده می‌کند.
# ایجاد حالت اولیه، با دادن نام فایل و ورودی نمادین به عنوان آرگومان دوم (argv[1])
state = proj.factory.entry_state(args=[binary_name, password_symbol])

# برای محدود کردن کاراکترهای پسورد به کاراکترهای قابل چاپ ASCII
# (اختیاری، اما برای پسوردهای متنی بسیار مفید است)
for i in range(SYMBOLIC_PASSWORD_LEN):
    # کاراکترهای قابل چاپ: 0x20 (Space) تا 0x7e (~)
    # این محدودیت را به حل‌کننده (Solver) اضافه می‌کنیم
    # اگر ورودی را با read یا scanf بگیرید، باید بایت پایانی (null byte) را نیز در نظر بگیرید.
    state.solver.add(password_symbol.get_byte(i) >= 0x20, password_symbol.get_byte(i) <= 0x7e)

print("[*] شروع اجرای نمادین (Symbolic Execution) برای یافتن مسیر موفقیت...")
# ایجاد مدیر شبیه‌سازی (Simulation Manager) برای مدیریت مسیرهای اجرای نمادین
simgr = proj.factory.simulation_manager(state)

# اجرای کاوش (Explore)
# ما به دنبال حالتی هستیم که به FIND_ADDR برسد و از AVOID_ADDR دوری کند.
simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

# بررسی نتایج
if simgr.found:
    print("[+] پسورد با موفقیت یافت شد!")
    found_state = simgr.found[0]
    
    # استخراج مقدار concrete (واقعی) برای ورودی نمادین
    # .eval() مقدار concrete (ملموس) را از یک BitVector نمادین استخراج می‌کند.
    # bytestring_password = found_state.solver.eval(password_symbol, cast_to=bytes)
    
    # برای جلوگیری از اضافه شدن null byte های احتمالی که angr به صورت پیش فرض در نظر می‌گیرد:
    # ابتدا مقدار عددی را استخراج کرده
    numeric_password = found_state.solver.eval(password_symbol)
    
    # سپس آن را به بایت تبدیل کرده و null bytes و space های انتهایی را حذف می‌کنیم
    bytestring_password = found_state.solver.eval(password_symbol, cast_to=bytes).strip(b'\x00').strip(b' ')
    
    print(f"[*] پسورد (بایت): {bytestring_password}")
    try:
        # نمایش پسورد به صورت رشته ASCII
        final_password = bytestring_password.decode('ascii')
        print(f"[*] پسورد نهایی: **{final_password}**")
        
        # اگر رمز عبور شامل کاراکترهای غیر قابل چاپ باشد، try/except به کار می‌آید
    except UnicodeDecodeError:
        print("[!] پسورد شامل کاراکترهای غیرقابل چاپ است.")
        print(f"[*] پسورد (Hex): {bytestring_password.hex()}")

else:
    print("[-] متأسفانه، پسورد یافت نشد. ممکن است آدرس‌های FIND_ADDR/AVOID_ADDR اشتباه باشند یا برنامه قابل حل با این روش نباشد.")