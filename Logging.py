"""Logging"""
import subprocess
from datetime import datetime


class LogFiles:
    """Log Files"""

    def __init__(self):
        now = datetime.now()
        self.log_path = "logs"
        self.folder_name_mngmt = now.strftime("fuzz_mngmt_frames")
        self.folder_name_ctrl = now.strftime("fuzz_ctrl_frames")
        self.folder_name_data = now.strftime("fuzz_data_frames")
        self.folder_path_mngmt = f"{self.log_path}/{self.folder_name_mngmt}"
        self.folder_path_ctrl = f"{self.log_path}/{self.folder_name_ctrl}"
        self.folder_path_data = f"{self.log_path}/{self.folder_name_data}"
        self.is_alive_path_mngmt = self.folder_path_mngmt + now.strftime(
            "/aliveness_check_%d-%m-%y__%H:%M:%S"
        )
        self.is_alive_path_ctrl = self.folder_path_ctrl + now.strftime(
            "/aliveness_check_%d-%m-%y__%H:%M:%S"
        )
        self.is_alive_path_data = self.folder_path_data + now.strftime(
            "/aliveness_check_%d-%m-%y__%H:%M:%S"
        )
        self.frames_till_disr_mngmt = self.folder_path_mngmt + now.strftime(
            "/frames_till_disr_%d-%m-%y__%H:%M:%S"
        )
        self.frames_till_disr_ctrl = self.folder_path_ctrl + now.strftime(
            "/frames_till_disr_%d-%m-%y__%H:%M:%S"
        )
        self.frames_till_disr_data = self.folder_path_data + now.strftime(
            "/frames_till_disr_%d-%m-%y__%H:%M:%S"
        )

        for path in [
            self.log_path,
            self.folder_path_mngmt,
            self.folder_path_ctrl,
            self.folder_path_data,
        ]:
            subprocess.call([f"mkdir -p {path}"], shell=True)

    def logging_conn_loss(self, reason, write_to):
        """logging_conn_loss"""
        with open(write_to, "a", encoding="latin1") as file_handle:
            now = datetime.now()
            file_handle.write(now.strftime("%H:%M:%S") + ": " + reason)
