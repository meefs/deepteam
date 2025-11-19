from .aegis.aegis import Aegis
from .beavertails.beavertails import BeaverTails
from .owasp.owasp import OWASPTop10
from .nist.nist import NIST
from .mitre.mitre import MITRE


FRAMEWORKS_MAP = {
    f.name: f
    for f in [
        OWASPTop10,
        NIST,
        MITRE
    ]
}

FRAMEWORK_RISK_CATEGORIES_MAP = {
    f.name: f.ALLOWED_TYPES
    for f in [
        OWASPTop10,
        NIST,
        MITRE
    ]
}

DATASET_FRAMEWORKS_MAP = {
    f.name: f
    for f in [
        Aegis,
        BeaverTails
    ]
}