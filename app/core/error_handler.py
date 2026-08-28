# Compatibilité rétroactive : tous les imports existants qui pointent vers
# app.core.error_handler continuent de fonctionner. La vraie implémentation
# se trouve désormais dans app.utils.error_handler.
from app.utils.error_handler import *  # noqa: F401, F403