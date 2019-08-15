# -*- mode: python -*-
a = Analysis(['scripts/cb-joesandbox-connector'],
             pathex=['.'],
             hiddenimports=['unicodedata'],
             datas=[ (HOMEPATH + '/cbapi/response/models/*', 'cbapi/response/models/'),
                     (HOMEPATH + '/cbapi/protection/models/*', 'cbapi/protection/models/'),
                     (HOMEPATH + '/cbapi/psc/defense/models/*', 'cbapi/psc/defense/models/'),
                     (HOMEPATH + '/cbapi/psc/livequery/models/*', 'cbapi/psc/livequery/models/'),
                     (HOMEPATH + '/cbapi/psc/threathunter/models/*', 'cbapi/psc/threathunter/models/'),
                   ],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='cb-joesandbox-connector',
          debug=False,
          strip=None,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               name='cb-joesandbox-connector')
