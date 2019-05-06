import socket

from OpenSSL import SSL

import mitmproxy.net.tcp
from mitmproxy import tcp
from mitmproxy import flow
from mitmproxy import exceptions
from mitmproxy.proxy.protocol import base
from mitmproxy.proxy.protocol.systemmodel import SystemModel

from jpype import *
import subprocess
import types
import sys,imp
import copy

class RawTCPLayer(base.Layer):
    chunk_size = 4096

    def __init__(self, ctx, ignore=False):
        self.ignore = ignore
        #self.jar = "-Djava.class.path=alloy4.2.jar"
        #self.filename = "phone_camera_minimum.als"
        #print(ctx.client_conn)
        #self.state_machine_created = False
        #self.device_to_ip = {}
        #self.previous_system = {}
        #self.safety_functions = []
        #self.device_to_mac = {}
        #self.device_to_mac["Phone"] = "f0:0f:ec:ee:6b:27"
        #self.device_to_mac["Camera"] = "00:00:00:00:00:00"

        super().__init__(ctx)

    def __call__(self):
        self.connect()
        print ("RawTCPLayer called")
        if not self.ignore:
            f = tcp.TCPFlow(self.client_conn, self.server_conn, self)
            self.channel.ask("tcp_start", f)

        buf = memoryview(bytearray(self.chunk_size))

        client = self.client_conn.connection
        server = self.server_conn.connection
        conns = [client, server]

        try:
            while not self.channel.should_exit.is_set():
                r = mitmproxy.net.tcp.ssl_read_select(conns, 10)
                for conn in r:
                    dst = server if conn == client else client

                    size = conn.recv_into(buf, self.chunk_size)
                    if not size:
                        conns.remove(conn)
                        # Shutdown connection to the other peer
                        if isinstance(conn, SSL.Connection):
                            # We can't half-close a connection, so we just close everything here.
                            # Sockets will be cleaned up on a higher level.
                            return
                        else:
                            dst.shutdown(socket.SHUT_WR)

                        if len(conns) == 0:
                            return
                        continue

                    tcp_message = tcp.TCPMessage(dst == server, buf[:size].tobytes())
                    if not self.ignore:
                        f.messages.append(tcp_message)
                        self.channel.ask("tcp_message", f)
 
                    #print("client laddr: " , client.getsockname(), " client raddr: ", client.getpeername())
                    #print("client: ", client)
                    #print("server laddr: " , server.getsockname(), " client server: ", server.getpeername())
                    #print("server: ", server)

                    #note conn.getpeername() returns the device/server connected
                    #print("type of getsockname()[0]: ", type(client.getpeername()[0]))
                    device_ip = client.getpeername()[0].replace(":", "")
                    device_ip = device_ip.replace("f", "")

                    #if function determines should not block device
                    if not SystemModel.block_device(device_ip, tcp_message.content, dst, client, server):
                        dst.sendall(tcp_message.content)

        except (socket.error, exceptions.TcpException, SSL.Error) as e:
            if not self.ignore:
                f.error = flow.Error("TCP connection closed unexpectedly: {}".format(repr(e)))
                self.channel.tell("tcp_error", f)
        finally:
            if not self.ignore:
                self.channel.tell("tcp_end", f)

    #def update_device_ip(self, device):
    #    result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE)
    #    mac = self.device_to_mac[device]
    #    for line in result.stdout.decode("utf-8").splitlines():
    #        if mac in line:
    #            self.device_to_ip[device] = line[line.index('(') + 1 : line.index(')') ]

    #def device_connected(self, device):
    #    result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE)
    #    mac = self.device_to_mac[device]

    #    if mac in result.stdout.decode("utf-8"):
    #        self.update_device_ip(device) #update device ip
    #        return True
    #    else:
    #        return False

    #def update_state_machine(self, content):
    #    #print (self.system)

    #    #update location        
    #    for device in self.system:
    #        self.system[device]["location"] = "Inside" if self.device_connected(device) else "Outside"

    #    for f in self.safety_functions:
    #        if f(self, self.system) is False:
    #            return False

    #    return True

    #def generate_state_machine(self, filename, ans, world):
    #    #parses file to create state model of system
    #    sigs = None
    #    device = None
        
    #    sigs = world.getAllSigs()
    #    for sig in sigs.makeCopy():
    #        if "Device" in sig.toString():
    #            device = sig

    #    self.system = {}
    #    self.state_safety = {}
    #    f = open(filename, "r")
    #    fl = f.readlines()
    #    for l in fl:
    #        if "assert" in l:
    #            self.add_safety_function(l)
    #        idx = l.find(" extends Device")
    #        if idx != -1:
    #            oidx = l.find("sig ")
    #            name = l[oidx+4:idx]
    #            self.system[name] = {}
    #            for field in device.getFields().makeCopy():
    #                fidx = field.toString().find("<:")
    #                pidx = field.toString().find(")")
    #                self.system[name][field.toString()[fidx+3:pidx]] = None

    #    self.system['Camera']['state'] = 'OFF'
    #    f.close()

    #def add_safety_function(self, line):
    #    code = """def a1 (self, system): 
    #        return system['Camera']['state'] is 'OFF' or system['Phone']['location'] is 'outside'
    #    """
    #    module = imp.new_module("safetyfunctions")
    #    exec (code, module.__dict__ )
    #    self.safety_functions.append(module.a1)

    #def alloy_model(self, jar, filename):
    #    #print("isJVMStarted(): " + str(isJVMStarted()))
    #    if not isJVMStarted():
    #        print ("start jvm")
    #        startJVM(getDefaultJVMPath(), "-ea", jar)

    #    #print("isThreadAttachedToJVM(): " + str(isThreadAttachedToJVM()))
    #    if not isThreadAttachedToJVM():
    #        print ("attach to jvm")
    #        attachThreadToJVM()

    #    a4opt = JClass('edu.mit.csail.sdg.alloy4compiler.translator.A4Options')
    #    satsolver =  JClass('edu.mit.csail.sdg.alloy4compiler.translator.A4Options$SatSolver')
    #    A4Reporter = JClass('edu.mit.csail.sdg.alloy4.A4Reporter')
    #    CompUtil = JClass ('edu.mit.csail.sdg.alloy4compiler.parser.CompUtil')
    #    TranslateAlloyToKodkod = JClass('edu.mit.csail.sdg.alloy4compiler.translator.TranslateAlloyToKodkod')#

    #    rep = A4Reporter()
    #    options = a4opt()
    #    options.solver = satsolver.SAT4J

    #    #java.lang.System.out.println("=========== Parsing+Typechecking "+filename+" =============")
    #    world = CompUtil.parseEverything_fromFile(rep, None, filename)
    #    #print (world)

    #    satisfiable = True

    #    for command in world.getAllCommands():
    #      #java.lang.System.out.println("============ Command "+command.toString()+": ============")
    #      ans = TranslateAlloyToKodkod.execute_command(rep, world.getAllReachableSigs(), command, options)
    #      #java.lang.System.out.println(ans.toString())
    #      #java.lang.System.out.println("============ Satisfiable: "+ str(ans.satisfiable()) +" ============")
    #      #self.ans = ans
    #      #self.world = world
    #      #print ("world: " + str(world))
    #      satisfiable = ans.satisfiable()
    #    return satisfiable, ans, world
