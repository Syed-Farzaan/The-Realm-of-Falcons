from falcon import bcolors

def logo():
    print(bcolors.ORANGE, end='')
    logo_ascii = '''
                                              						.ze$$e.
								      .ed$$$eee..      .$$$$$$$P""
								   z$$$$$$$$$$$$$$$$$ee$$$$$$"
								.d$$$$$$$$$$$$$$$$$$$$$$$$$"
							      .$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$e..
							    .$$****""""***$$$$$$$$$$$$$$$$$$$$$$$$$$$be.
									     ""**$$$$$$$$$$$$$$$$$$$$$$$L
						The Guardians Of Justice       z$$$$$$$$$$$$$$$$$$$$$$$$$
				      	       Into The Spiral Dimensions    .$$$$$$$$P**$$$$$$$$$$$$$$$$
									    d$$$$$$$"              4$$$$$
									  z$$$$$$$$$                $$$P"
									 d$$$$$$$$$F                $P"
									 $$$$$$$$$$F
									  *$$$$$$$$"   Created by: Syed Bukhari, Sheikh Arsalan
									    "***""     Version-1.0.8

                                    				'''+bcolors.RESET+'''(A Multi-Tool Web Vulnerability Scanner)
                                 				   Catch us on Twitter: '''+bcolors.BG_LOW_TXT+'''@0xTheFalconX'''+bcolors.RESET+'''
    '''
    print(logo_ascii, end='')
    print(bcolors.RESET, end='')
