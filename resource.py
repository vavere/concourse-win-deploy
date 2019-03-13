#!/usr/bin/env python2

import os
import sys
import json
import time
import string
import random
import socket
import codecs
import tempfile
import logging
from smb.SMBConnection import SMBConnection # https://pysmb.readthedocs.io/en/latest/api/smb_SMBConnection.html
from smb.smb_structs import OperationFailure
from pypsexec.client import Client # https://github.com/jborean93/pypsexec

LOGLEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level="ERROR", format='%(levelname)s: %(message)s')
log = logging.getLogger("resource")
log.setLevel(level=LOGLEVEL)

ADMIN_SERVICE = "admin$"
MAGICK_FILENAME = "concourse_win_deply"

def temp_name(size=8, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
        
def parse_source(source):
    host = source.get('host')
    port = source.get('port', 445)
    username = source.get('user', os.environ.get('WIN_USER'))
    password = source.get('pass', os.environ.get('WIN_PASS'))
    encrypt = source.get('encrypt', False)

    log.debug('host: "%s"', host)
    log.debug('port: "%s"', port)
    log.debug('user: "%s"', username)
    log.debug('pass: "%s"', password)
    log.debug('encrypt: "%s"', encrypt)
    
    if host is None or username is None or password is None:
        raise ValueError("Resource host, user and pass is mandatory!")
    return host, port, username, password, encrypt
    
def get_version(source):
    host, port, username, password, encrypt = parse_source(source)

    ip = socket.gethostbyname(host)
    localhost = socket.gethostname()
    
    log.info('connecting "%s" ...', host)
    conn = SMBConnection(username, password, localhost, host, use_ntlm_v2=True, is_direct_tcp=True)
    ready = conn.connect(ip, 445)
    if not ready:
        raise Exception("Connect failed, host, user or pass is not valid!")
    
    # version magick
    log.info('get version ...')
    try:
        attr = conn.getAttributes(ADMIN_SERVICE, MAGICK_FILENAME)
        version = attr.last_write_time
    except OperationFailure:
        version = None

    conn.close()
    return str(version)
        
class Resource(object):
  
    def run(self, command):
        if sys.stdin.isatty():
            raise ValueError("No valid input resceived")
        try:
            input = json.loads(sys.stdin.read())
        except ValueError as e:
            raise ValueError("Input json data not well-formed: %s" % e)
    
        source = input.get('source', {})
        params = input.get('params', {})
        version = input.get('version', {})
        folder = sys.argv[1] if len(sys.argv) > 1 else ""
        if source.get('debug', False):
          log.setLevel(logging.DEBUG)
            
        log.debug('command: "%s"', command)
        log.debug('input: "%s"', source)
        log.debug('params: "%s"', params)
        log.debug('version: "%s"', version)
        log.debug('folder: "%s"', folder)
        log.debug('environment: %s', os.environ)
    
        if command == 'check':
            response = self.check(source, version)
        elif command == 'in':
            response = self.do_in(source, version, params, folder)
        elif command == 'out':
            response = self.do_out(source, params, folder)
        else:
            raise ValueError("Invalid command: '%s'" % command)
    
        log.debug('response: "%s"', response)
        output = json.dumps(response, indent=2, separators=(',', ': '))
        sys.stdout.write(str(output) + '\n')
        
    def check(self, source, version):
        return [{"timestamp": get_version(source)}]

    def do_in(self, source, version, params, folder):
        return {"version": {"timestamp": get_version(source)}, "metadata": []}      
        
    def do_out(self, source, params, folder):
        host, port, username, password, encrypt = parse_source(source)
            
        file = params.get('file')
        log.debug('file: "%s"', file)
        
        if file is None:
            raise ValueError("File name in params is mandatory!")
        
        filename = os.path.basename(file)
        filepath = os.path.join(folder, file)
        if not os.path.exists(filepath):
            raise Exception("File '%s' not found!" % filepath)
        
        ip = socket.gethostbyname(host)
        localhost = socket.gethostname()
        
        # connect smb share
        log.info('connecting "%s" ...', host)
        conn = SMBConnection(username, password, localhost, host, use_ntlm_v2 = True, is_direct_tcp=True)
        ready = conn.connect(ip, 445)
        if not ready:
            raise Exception("Connect failed, host, user or pass is not valid!")
        
        # create temp folder and move package to
        remote_dir = "temp\\%s" % temp_name()
        conn.createDirectory(ADMIN_SERVICE, remote_dir)
   
        # copy package remote
        file_obj = open(filepath, 'r')
        remote_filepath = "%s\\%s" % (remote_dir, filename)
        conn.storeFile(ADMIN_SERVICE, remote_filepath, file_obj)
        file_obj.close()
        
        # install package remotely
        log.info('installing "%s" ...', filename)
        psexec = Client(ip, username=username, password=password, encrypt=encrypt)
        psexec.connect()
        try:
            psexec.create_service()
            msi_path = "%systemroot%\\" + remote_filepath
            log_path = "%systemroot%\\" + remote_dir + "\\msiexec.log"
            cmd = "msiexec /i %s /qn /norestart /L*v %s" % (msi_path, log_path)
            log.debug(cmd)
            stdout, stderr, rc = psexec.run_executable("cmd.exe", arguments="/c " + cmd)
            if rc != 0:
                raise Exception(stdout.decode('utf-16'))
        finally:
            psexec.remove_service()
            psexec.disconnect()        
        
        # copy log localy and dump
        remote_logpath = remote_dir + "\\msiexec.log"
        logpath = os.path.join(tempfile.gettempdir(), temp_name())
        log_obj = open(logpath, "w")
        conn.retrieveFile(ADMIN_SERVICE, remote_logpath, log_obj)
        log_obj.close()
        with codecs.open(logpath, 'r', encoding="utf-16") as log_file:
            log.debug(log_file.read())
        os.remove(logpath)
        
        # version magick
        log.info('set version ...')
        with tempfile.NamedTemporaryFile() as ver_obj:
            conn.storeFile(ADMIN_SERVICE, MAGICK_FILENAME, ver_obj)
        attr = conn.getAttributes(ADMIN_SERVICE, MAGICK_FILENAME)
        version = attr.last_write_time
    
        # clean and diconnect
        conn.deleteFiles(ADMIN_SERVICE, remote_logpath)
        conn.deleteFiles(ADMIN_SERVICE, remote_filepath)
        conn.deleteDirectory(ADMIN_SERVICE, remote_dir)
        conn.close()
        
        return {"version": {"timestamp": str(version)}, "metadata": []}
      
if __name__ == '__main__':
    r = Resource()
    try:
        r.run(os.path.basename(__file__))
    except Exception as e:
        log.error(str(e))
        sys.exit(1)
 