from mafkit.attack import map_capabilities

def test_attack_mapping_detected_only():
    x=map_capabilities({'sms':{'detected':True,'evidence':['SmsManager']},'websocket':{'detected':False,'evidence':[]}}); assert len(x)==1 and x[0]['capability']=='sms'
def test_attack_mapping_unknown_ignored(): assert map_capabilities({'unknown':{'detected':True}})==[]
