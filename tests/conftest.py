from pathlib import Path
import sys

BASEDIR = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASEDIR))
