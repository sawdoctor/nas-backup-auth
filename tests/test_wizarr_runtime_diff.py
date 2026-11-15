"""A diagnostic must identify drift without emitting secret values."""
import importlib.util
import json
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[1]/'scripts/inspect-nas-wizarr-runtime-diff.py'
spec=importlib.util.spec_from_file_location('wizarr_diff',path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class WizarrDiffTests(unittest.TestCase):
    def test_runtime_representation_and_real_controls_are_reported(self):
        before={'Binds':['secret-source:/data'], 'Mounts':[], 'Init':None,'Memory':0,'ConsoleSize':[0,0]}
        after={'Binds':None, 'Mounts':[{'Source':'secret-source'}], 'Init':False,'Memory':1024,'ConsoleSize':[0,0]}
        result=m.safe_host_diff(before,after)
        self.assertEqual(result['Binds'],{'beforeCount':1,'currentCount':0})
        self.assertEqual(result['Memory'],{'before':0,'current':1024})
        self.assertNotIn('secret-source',json.dumps(result))
        self.assertNotIn('ConsoleSize',result)

    def test_secret_environment_and_log_option_values_are_withheld(self):
        result=m.env_diff({'KEY':'SECRET','EXTRA':'SECRET'},{'KEY':'OTHER-SECRET','MISSING':'SECRET'})
        self.assertEqual(result,{'missingNames':['MISSING'],'additionalNames':['EXTRA'],'differentNames':['KEY']})
        diff=m.safe_host_diff({'LogConfig':{'Type':'json-file','Config':{'env':'SECRET','max-size':'10m'}}},
                             {'LogConfig':{'Type':'json-file','Config':{'env':'OTHER-SECRET','max-size':'20m'}}})
        self.assertNotIn('SECRET',json.dumps(diff));self.assertEqual(diff['LogConfig']['max-size']['current'],'20m')

if __name__=='__main__':unittest.main()
