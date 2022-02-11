import adexpsnapshot
import os

def test_full_parse():
    path = os.path.join(os.path.dirname(__file__), 'data/detectionlab.dat')
    fh = open(path, "rb")
    ades = adexpsnapshot.ADExplorerSnapshot(fh, '/tmp')
    ades.outputBloodHound()
    ades.outputObjects()
