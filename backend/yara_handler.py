# yara_handler.py
import yara
import os
from typing import Dict, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class YaraHandler:
    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize YARA handler with rules.
        Args:
            rules_path: Path to YARA rules file. If None, uses embedded rules.
        """
        self.rules_path = rules_path or os.path.join(
            os.path.dirname(__file__),
            "rules",
            "malware_rules.yar"
        )
        self.rules = self._initialize_rules()

    def _initialize_rules(self):
        """Initialize YARA rules from file"""
        try:
            if os.path.exists(self.rules_path):
                return yara.compile(filepath=self.rules_path)
            else:
                logger.error(f"YARA rules file not found at {self.rules_path}")
                raise FileNotFoundError(f"YARA rules file not found at {self.rules_path}")
        except yara.Error as e:
            logger.error(f"Failed to compile YARA rules: {str(e)}")
            raise

    def scan_file(self, file_path: str) -> Dict:
        """
        Scan a file using YARA rules.
        Args:
            file_path: Path of the file to scan.
        Returns:
            Dict containing scan results.
        """
        if not self.rules:
            raise Exception("YARA rules are not initialized")

        try:
            # If the file is a .bat script, read it as text
            # if file_path.endswith(".bat"):
            #     with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            #         file_content = f.read()
            #     matches = self.rules.match(data=file_content)  # Scan text content
            # else:
            print(file_path,self.rules)
            matches = self.rules.match(file_path)  # Scan as binary
            print(matches)
            results = {
                "timestamp": datetime.now().isoformat(),
                "matches": [],
                "summary": {
                    "total_matches": str(matches),
                    "risk_level": self._calculate_risk_level(matches),
                    "matched_rules": [match.rule for match in matches]
                }
            }

            # for match in matches:
            #     match_details = {
            #         "rule_name": match.rule,
            #         "tags": match.tags,
            #         "meta": match.meta if hasattr(match, 'meta') else {},
            #         "strings": []
            #     }

            #     if hasattr(match, 'strings'):
            #         for string_match in match.strings:
            #             string_id, string_offset, string_data = string_match
            #             try:
            #                 decoded_data = string_data.decode('utf-8', errors='ignore')
            #             except Exception:
            #                 decoded_data = str(string_data)

            #             match_details["strings"].append({
            #                 "id": string_id,
            #                 "offset": string_offset,
            #                 "data": decoded_data
            #             })

            #     results["matches"].append(match_details)

            logger.info(f"Completed YARA analysis with {len(matches)} matches")
            return results

        except Exception as e:
            logger.error(f"YARA scanning failed: {str(e)}")
            raise

    def _calculate_risk_level(self, matches: List) -> str:
        """
        Calculate risk level based on YARA matches.
        Args:
            matches: List of YARA matches.
        Returns:
            Risk level as a string.
        """
        if not matches:
            return "clean"

        # Define critical rules that indicate high risk
        critical_rules = {
            "Ransomware_Indicators",
            "Process_Injection",
            "Data_Exfiltration",
            "Keylogger_Behavior"
        }

        # Count matches by severity
        critical_matches = sum(1 for match in matches if match.rule in critical_rules)
        total_matches = len(matches)

        # Calculate risk level
        if critical_matches > 0:
            return "high"
        elif total_matches > 5:
            return "medium"
        elif total_matches > 0:
            return "low"
        else:
            return "clean"

# import yara
# import os
# from typing import Dict, List, Optional
# from datetime import datetime
# import logging

# # Configure logger
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.INFO)

# class YaraHandler:
#     def __init__(self, rules_path: Optional[str] = None):
#         """
#         Initialize YARA handler with rules.
#         Args:
#             rules_path: Path to YARA rules file. If None, uses embedded rules.
#         """
#         self.rules_path = rules_path or os.path.join(
#             os.path.dirname(__file__),
#             "rules",
#             "malware_rules.yar"
#         )
#         self.rules = self._initialize_rules()

#     def _initialize_rules(self):
#         """Initialize YARA rules from file"""
#         try:
#             if os.path.exists(self.rules_path):
#                 logger.info(f"Loading YARA rules from {self.rules_path}")
#                 return yara.compile(filepath=self.rules_path)
#             else:
#                 logger.error(f"YARA rules file not found: {self.rules_path}")
#                 raise FileNotFoundError(f"YARA rules file not found at {self.rules_path}")
#         except yara.Error as e:
#             logger.error(f"Failed to compile YARA rules: {str(e)}")
#             raise

#     def scan_file(self, file_path: str) -> Dict:
#         """
#         Scan a file using YARA rules.
#         Args:
#             file_path: Path of the file to scan.
#         Returns:
#             Dict containing scan results.
#         """
#         if not self.rules:
#             raise Exception("YARA rules are not initialized")

#         if not os.path.exists(file_path):
#             logger.error(f"File not found: {file_path}")
#             raise FileNotFoundError(f"Target file {file_path} does not exist")

#         try:
#             logger.info(f"Scanning file: {file_path}")
#             matches = self.rules.match(file_path)  # Scan as binary
    
#             results = {
#                 "timestamp": datetime.now().isoformat(),
#                 "matches": [],
#                 "summary": {
#                     "total_matches": len(matches),
#                     # "risk_level": self._calculate_risk_level(matches),
#                     "risk_level": str(matches), 
#                     "matched_rules": [match.rule for match in matches]
#                 }
#             }

#             # for match in matches:
#             #     match_details = {
#             #         "rule_name": match.rule,
#             #         "tags": match.tags,
#             #         "meta": match.meta if hasattr(match, 'meta') else {},
#             #         "strings": []
#             #     }

#             #     if hasattr(match, 'strings'):
#             #         for string_match in match.strings:
#             #             string_id, string_offset, string_data = string_match
#             #             try:
#             #                 decoded_data = string_data.decode('utf-8', errors='ignore')
#             #             except Exception:
#             #                 decoded_data = str(string_data)

#             #             match_details["strings"].append({
#             #                 "id": string_id,
#             #                 "offset": string_offset,
#             #                 "data": decoded_data
#             #             })

#             #     results["matches"].append(match_details)

#             logger.info(f"Completed YARA analysis with {len(matches)} matches")
#             return results

#         except yara.Error as e:
#             logger.error(f"YARA scanning error: {str(e)}")
#             return {
#                 "timestamp": datetime.now().isoformat(),
#                 "matches": [],
#                 "summary": {
#                     "total_matches": 0,
#                     "risk_level": "error",
#                     "matched_rules": [],
#                     "error": str(e)
#                 }
#             }
#         except Exception as e:
#             logger.error(f"Unexpected scanning failure: {str(e)}")
#             raise

#     def _calculate_risk_level(self, matches: List) -> str:
#         """
#         Calculate risk level based on YARA matches.
#         Args:
#             matches: List of YARA matches.
#         Returns:
#             Risk level as a string.
#         """
#         if not matches:
#             return "clean"

#         # Define high-risk rules
#         critical_rules = {
#             "Ransomware_Indicators",
#             "Process_Injection",
#             "Data_Exfiltration",
#             "Keylogger_Behavior"
#         }

#         critical_matches = sum(1 for match in matches if match.rule in critical_rules)
#         total_matches = len(matches)

#         if critical_matches > 0:
#             return "high"
#         elif total_matches >= 3:
#             return "medium"
#         elif total_matches > 0:
#             return "low"
#         else:
#             return "clean"
