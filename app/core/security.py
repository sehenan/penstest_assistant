# Compatibilité rétroactive : tous les imports existants qui pointent vers
# app.core.security continuent de fonctionner. La vraie implémentation
# se trouve désormais dans app.utils.security.
from app.utils.security import *  # noqa: F401, F403