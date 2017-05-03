#!/usr/bin/env python
#
# Copyright 2015 Alternative Systems All Rights Reserved
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met:
#
# *   Redistributions of source code must retain the above copyright notice, 
#       this list of conditions and the following disclaimer. 
# *   Redistributions in binary form must reproduce the above copyright notice, 
#       this list of conditions and the following disclaimer in the 
#       documentation and/or other materials provided with the distribution. 
# *   Neither the name of the Alternative Systems LLC nor the names of its 
#       contributors may be used to endorse or promote products derived from 
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE ALTSYSTEM OR CONTRIBUTORS BE LIABLE FOR 
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# EXPORT LAWS: THIS LICENSE ADDS NO RESTRICTIONS TO THE EXPORT LAWS OF YOUR 
# JURISDICTION. It is licensee's responsibility to comply with any export 
# regulations applicable in licensee's jurisdiction. Under CURRENT (Dec 2015) 
# U.S. export regulations this software is eligible for export from the U.S. 
# and can be downloaded by or otherwise exported or reexported worldwide EXCEPT 
# to U.S. embargoed destinations which include Cuba, Iraq, Libya, North Korea, 
# Iran, Syria, Sudan, Afghanistan and any other country to which the U.S. has 
# embargoed goods and services.

COINS   =   {
                # Not really a coin, but still here to differentiate it from actual networks
                'Infiniti'         : {
                                'main'  :   {
                                                'private'   :   '31526e67',
                                                'public'    :   '31526e67',
                                                'prefix'    :   '67',
                                                'script'    :   '7a',
                                                'secret'    :   '80',
                                                'xkeypub'   :   'inf',
                                                'xkeyprv'   :   'inf'

                                            },
                                'abbr'  :   'Inf'
                            },
                'Bitcoin'       : {
                                'main'  :   {
                                                'private'   :   '0488ade4',
                                                'public'    :   '0488b21e',
                                                'prefix'    :   '00',
                                                'script'    :   '05',
                                                'secret'    :   '80',
                                                'xkeypub'   :   'xpub',
                                                'xkeyprv'   :   'xprv'

                                            },
                                'test'  :   {
                                                'private'   :   '04358394',
                                                'public'    :   '043587cf',
                                                'prefix'    :   '6f',
                                                'script'    :   'c4',
                                                'secret'    :   'ef',
                                                'xkeypub'   :   'xpub',
                                                'xkeyprv'   :   'xprv'
                                },
                                'abbr'  :   'BTC'
                            },
                'Tao'           : {
                                'main'  :   {
                                                'private'   :   '0488ade4',
                                                'public'    :   '0488b21e',
                                                'prefix'    :   '42',
                                                'script'    :   '03',
                                                'secret'    :   '4c',
                                                'xkeypub'   :   'xpub',
                                                'xkeyprv'   :   'xprv'
                                            },
                                'test'  :   {
                                                'private'   :   '04358394',
                                                'public'    :   '043587cf',
                                                'prefix'    :   '7f',
                                                'script'    :   '82',
                                                'secret'    :   '8a',
                                                'xkeypub'   :   'xpub',
                                                'xkeyprv'   :   'xprv'
                                },
                                'abbr'  :   'XTO'
                            },
            }