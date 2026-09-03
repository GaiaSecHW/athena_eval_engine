"""共享枚举（与 schema.sql CHECK 对齐）。"""
from enum import Enum


class Condition(str, Enum):
    KG = "KG"
    NOGK = "NOGK"
    UNKNOWN = "UNKNOWN"


class ConditionSource(str, Enum):
    MANIFEST = "MANIFEST"
    TRACE_METADATA = "TRACE_METADATA"
    ENV_METADATA = "ENV_METADATA"
    FILENAME = "FILENAME"
    UNKNOWN = "UNKNOWN"


class Outcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAIL = "FAIL"
    UNDETERMINED = "UNDETERMINED"


class Prediction(str, Enum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    UNDETERMINED = "UNDETERMINED"


class Confusion(str, Enum):
    TP = "TP"; FP = "FP"; FN = "FN"; TN = "TN"; NA = "NA"


class ExpectedLabel(str, Enum):
    VULNERABLE = "VULNERABLE"
    NON_VULNERABLE = "NON_VULNERABLE"


class PairTransition(str, Enum):
    PRESERVED = "PRESERVED"
    REGRESSED = "REGRESSED"
    RECOVERED = "RECOVERED"
    PERSISTED_FAILURE = "PERSISTED_FAILURE"
    NA = "NA"


class PairMatchStatus(str, Enum):
    VALID_PAIR = "VALID_PAIR"
    INCOMPLETE = "INCOMPLETE"
    UNMATCHED = "UNMATCHED"


class CalculationStatus(str, Enum):
    CALCULATED = "CALCULATED"
    NA = "NA"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


class CanonicalAction(str, Enum):
    KG = "KG"; FINDING = "FINDING"; CODE = "CODE"; SHELL = "SHELL"; OTHER = "OTHER"
