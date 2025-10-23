import os
import time
from ugreen import process_ugreen
import traceback

# 从环境变量获取间隔时间，单位：分钟
INTERVAL_MINUTES = float(os.getenv("INTERVAL_MINUTES", 5))

while True:
    try:
        process_ugreen()
    except Exception as e:
        error_info = f"执行 process_ugreen 时出错: {e}\n{traceback.format_exc()}"
        print(error_info)

    time.sleep(INTERVAL_MINUTES * 60)
