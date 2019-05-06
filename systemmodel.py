from jpype import *
import subprocess
import types
import sys,imp
import copy

#static class with static variables 

class SystemModel:
    jar = "-Djava.class.path=alloy4.2.jar"
    filename = "phone_camera_minimum.als"

    system = {} #model of system
    previous_system = {}
    safety_functions = []

    statically_safe = False #if model run during init returned safe, so don't have to rerun alloy model

    device_to_mac = {}
    device_to_mac["Phone"] = "f0:0f:ec:ee:6b:27"
    device_to_mac["Camera"] = "00:00:00:00:00:00"

    device_to_ip = {}
    ip_to_device = {}

    world = None
    ans = None

    critical = {} #critical devices to never block
    critical["Phone"] = True
    critical["Camera"] = False

    fail_safe_block = {"Camera"}

    def update_device_ip(device):
        result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE)
        mac = SystemModel.device_to_mac[device]
        for line in result.stdout.decode("utf-8").splitlines():
            if mac in line:
                ip = line[line.index('(') + 1 : line.index(')')]
                SystemModel.device_to_ip[device] = ip
                SystemModel.ip_to_device[ip] = device

    def device_connected(device):
        result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE)
        mac = SystemModel.device_to_mac[device]

        if mac in result.stdout.decode("utf-8"):
            SystemModel.update_device_ip(device) #update device ip
            return True
        else:
            return False

   #returns whether this device should be blocked
    def block_device(device_ip, content, dst, client, server):
        dangerous = not SystemModel.statically_safe
        dangerous = True

        critical = False
        if device_ip in SystemModel.ip_to_device:
            critical = SystemModel.critical[SystemModel.ip_to_device[device_ip]]

        is_fail_safe_block_device = False
        if device_ip in SystemModel.ip_to_device:
            is_fail_safe_block_device = SystemModel.ip_to_device[device_ip] in SystemModel.fail_safe_block
 
        SystemModel.traffic_independent_update() #factors that will be updated whether traffic is blocked or no
        SystemModel.copy_system() #records now previous system to possibly revert later
        SystemModel.traffic_based_update(content, dst, client, server) #always update_state_machine
     
        need_fail_safe_block =  False
        # if system before and after is message is both unsafe, then trigger fail safe blocking mode
        if (not SystemModel.is_system_safe(SystemModel.system)) and (not SystemModel.is_system_safe(SystemModel.previous_system)):
            need_fail_safe_block = True

        #if statically safe or too critical to block, don't block
        if not SystemModel.statically_safe or critical:
            return False

        #only fail safe block if in fail safe blocking mode and this device needs to be blocked for fail safe
        elif is_fail_safe_block_device and need_fail_safe_block:
            return True

        else: #determine safety of message and then block accordingly
            return not SystemModel.is_system_safe(SystemModel.system)
            #blocks messages from client (to prevent information leaks)
           
    #returns whether system state is safe
    def traffic_based_update(content, dst, client, server):
        #system attributes actually gets updated

        pass

    def traffic_independent_update():
        #update location/power state
        for device in SystemModel.system:
            connected = SystemModel.device_connected(device)
            SystemModel.system[device]["location"] = "Inside" if connected else "Outside"
            SystemModel.system[device]["state"] = "ON" if connected else "OFF"
  
    #does state machine violate any of the safety assertions
    def is_system_safe(system):
        for f in SystemModel.safety_functions:
            if f(system) is False:
                return False
        return True
    
    def copy_system():
        SystemModel.previous_system = copy.deepcopy(SystemModel.system)

    def revert_previous_system():
        SystemModel.system = copy.deepcopy(SystemModel.previous_system)

    def generate_state_machine(world):
        #parses file to create state model of system
        sigs = None
        device = None
        
        assert (world is not None), "world is not null"
        sigs = world.getAllSigs()
        for sig in sigs.makeCopy():
            if "Device" in sig.toString():
                device = sig

        f = open(SystemModel.filename, "r")
        fl = f.readlines()
        for l in fl:
            if "assert" in l:
                SystemModel.add_safety_function(l)
            idx = l.find(" extends Device")
            if idx != -1:
                oidx = l.find("sig ")
                name = l[oidx+4:idx]
                SystemModel.system[name] = {}
                for field in device.getFields().makeCopy():
                    fidx = field.toString().find("<:")
                    pidx = field.toString().find(")")
                    SystemModel.system[name][field.toString()[fidx+3:pidx]] = None

        SystemModel.system['Camera']['state'] = 'OFF'
        f.close()

    def add_safety_function(line):
        code = """def a1 (system): 
            return system['Camera']['state'] is 'OFF' or system['Phone']['location'] is 'outside'
        """
        module = imp.new_module("safetyfunctions")
        exec (code, module.__dict__ )
        SystemModel.safety_functions.append(module.a1)


    def alloy_model(jar, filename):
        #print("isJVMStarted(): " + str(isJVMStarted()))
        if not isJVMStarted():
            print ("start jvm")
            startJVM(getDefaultJVMPath(), "-ea", jar)

        #print("isThreadAttachedToJVM(): " + str(isThreadAttachedToJVM()))
        if not isThreadAttachedToJVM():
            print ("attach to jvm")
            attachThreadToJVM()

        #import functions to run alloy
        a4opt = JClass('edu.mit.csail.sdg.alloy4compiler.translator.A4Options')
        satsolver =  JClass('edu.mit.csail.sdg.alloy4compiler.translator.A4Options$SatSolver')
        A4Reporter = JClass('edu.mit.csail.sdg.alloy4.A4Reporter')
        CompUtil = JClass ('edu.mit.csail.sdg.alloy4compiler.parser.CompUtil')
        TranslateAlloyToKodkod = JClass('edu.mit.csail.sdg.alloy4compiler.translator.TranslateAlloyToKodkod')

        rep = A4Reporter()
        options = a4opt()
        options.solver = satsolver.SAT4J

        world = CompUtil.parseEverything_fromFile(rep, None, filename)
        SystemModel.world = world
        satisfiable = False

        for command in world.getAllCommands():
          ans = TranslateAlloyToKodkod.execute_command(rep, world.getAllReachableSigs(), command, options)
          satisfiable = satisfiable or ans.satisfiable()

        SystemModel.statically_safe = not satisfiable
