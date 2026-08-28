# Compatibilité rétroactive : tous les imports existants qui pointent vers
# app.core.cache continuent de fonctionner. La vraie implémentation
# se trouve désormais dans app.utils.cache.
from app.utils.cache import *  # noqa: F401, F403