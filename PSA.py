#!/usr/bin/python

from datetime import datetime
import time

import pyws
from pyws.server import SoapServer
from pyws.functions.register import register
from pyws.adapters._wsgi import create_application
from pyws.functions.args import Integer,ListOf,DictOf,Field
from pyws.functions.args.types import DateTime

import random
import pyodbc
import threading

dblock = threading.Lock()
conn = pyodbc.connect('DSN=K2DW;CHARSET=UTF8',unicode_results=True)
result = conn.cursor();

class PSAServer(pyws.server.Server):
    def defaults(self):
        return pyws.settings.Settings( PROTOCOLS=(self.rest_protocol,self.soap_protocol) )
    def __init__(self, settings=None, *args, **kwargs):
        self.rest_protocol = pyws.protocols.RestProtocol()
        self.soap_protocol = pyws.protocols.SoapProtocol('PSA','http://k2advisors.com/portcon/','http://localhost:51235/psa/soap')
        super(PSAServer,self).__init__(settings)
        
#psa_server = PSAServer(settings={'DEBUG':False})
psa_server = PSAServer()
# Scenario object:
scenario = DictOf(
                'Scenario',
                    Field('ScenarioID',int),
                    Field('ScenarioName',str),
                    Field('ImplementationDate', datetime),
                    Field('Currency',str),
                    Field('CreatedBy',str),
                    Field('CreatedOn',datetime),
                    Field('ModifiedBy',str),
                    Field('ModifiedOn',datetime)
                    )

# Item object:
scenario_item = DictOf(
                    'ScenarioItem',
                        Field('ScenarioItemID',int),
                        Field('ScenarioVersion',int),
                        Field('k2_id',int),
                        Field('weight', float),
                        Field('CreatedBy',str),
                        Field('CreatedOn',datetime)
                        )
            
            
# GetScenario( string name ) # Called with Null string returns all
@register(return_type=scenario, args=(str,))
def GetScenario( ScenarioName ):
    """Get the Scenario object with a particular name"""
    if ScenarioName == "" or ScenarioName is None:
        return []
    scens = underlyingGetScenarios( ScenarioName )
    return scens[0]

@register(return_type=ListOf(scenario), args=())
def GetAllScenarios():
    """Get all available Scenario names"""
    print "GetAllScenarios"
    scenarios = underlyingGetScenarios()
    return scenarios

def underlyingGetScenarios( ScenarioName="" ):
    query = """SELECT 
                    ScenarioID, 
                    ScenarioName, 
                    ImplementationDate, 
                    Currency, 
                    CreatedBy, 
                    CreatedOn, 
                    ModifiedBy, 
                    ModifiedOn 
                FROM PortCon..tpc_psa_scenarios """
    
    where = """WHERE ScenarioName = CAST(? as varchar(60))"""
    
    with dblock:
        if ScenarioName == "" or ScenarioName is None:
            result.execute(query)
            res = result.fetchall()
        else:
            result.execute(query+where,ScenarioName)
            res = result.fetchall()
        
    objects = []
    for s in res:
        objects.append( {  'ScenarioID': s.ScenarioID,
                'ScenarioName': s.ScenarioName,
                'ImplementationDate': s.ImplementationDate,
                'Currency': s.Currency,
                'CreatedBy': s.CreatedBy,
                'CreatedOn': s.CreatedOn,
                'ModifiedBy': s.ModifiedBy,
                'ModifiedOn': s.ModifiedOn} )
    return objects
    
# GetScenarioItems( name, version) # null version returns latest
@register(return_type=ListOf(scenario_item), args=(str,(int,0)))
def GetScenarioItems( ScenarioName, Version=0 ):
    """Get the items stored with a particular name and version. If version is not given, the latest will be returned."""
    print "GetScenarioItems(",ScenarioName,",",Version,")"
    if Version < 0:
        raise Exception("Scenario Version must be a positive integer")
        
    if Version is None: Version = 0
    with dblock:
        result.execute("""SELECT
                            items.ScenarioItemID,
                            items.ScenarioVersion,
                            items.k2_id,
                            items.weight,
                            items.CreatedBy,
                            items.CreatedOn
                           FROM 
                            PortCon..tpc_psa_scenario_items items
                            INNER JOIN
                            PortCon..tpc_psa_scenarios scens
                            ON
                            items.ScenarioID = scens.ScenarioID
                           WHERE scens.ScenarioName = ? and (items.ScenarioVersion = ? or 
                            ( ? = 0 and scens.ModifiedOn = items.CreatedOn))""", ScenarioName, Version, Version)
    
        items = []
        for r in result.fetchall():
            items.append(dict((t[0], value) for t, value in zip(result.description, r)) )
    return items
    
# CreateScenario( name, currency, implementation date, user )
@register(return_type=int, args=(str,str,datetime))
def CreateScenario( ScenarioName, Currency, ImplementationDate ):
    """Create a new Scenario. Use SaveScenario after this to add items to the Scenario"""
    with dblock:
        result.execute("""SELECT ScenarioID FROM PortCon..tpc_psa_scenarios WHERE ScenarioName = CAST( ? as varchar(60))""", ScenarioName)
        exists = result.fetchall()
        if len(exists) > 0: 
            raise Exception("A Scenario with the name " + ScenarioName + " already exists")
            
        result.execute("""INSERT INTO PortCon..tpc_psa_scenarios (
                            ScenarioName,
                            ImplementationDate,
                            Currency,
                            CreatedBy,
                            CreatedOn,
                            ModifiedBy,
                            ModifiedOn 
                            ) VALUES (
                            ?,
                            ?,
                            (SELECT iso_numeric_code FROM K2DW..vdw_rpt_currency WHERE currency = CAST( ? as varchar(60)) ),
                            CURRENT_USER,
                            GETDATE(),
                            CURRENT_USER,
                            GETDATE()
                            )""", ScenarioName, ImplementationDate, Currency)
        conn.commit()
        result.execute("SELECT ScenarioID FROM PortCon..tpc_psa_scenarios WHERE ScenarioName = CAST( ? as varchar(60))",ScenarioName)
        id = result.fetchone()                    
    return id.ScenarioID
    
# SaveScenario( name, string[] ids, string[] weights ) 
@register(return_type=int, args=(str,[int],[float]))
def SaveScenario( ScenarioName, K2_IDs, Weights ):
    """Save items to a Scenario as a new version. It is not possible to edit a previous version, only add. Version numbers are integers and increment automatically."""
    print "SaveScenario(",ScenarioName, K2_IDs, Weights,")"
    if len(K2_IDs) != len(Weights):
        raise Exception("SaveScenario() must be passed the same number of k2_ids and weights")

    now = datetime.now()
    with dblock:
        result.execute("""SELECT 
                            scens.ScenarioID,
                            COALESCE(items.ScenarioVersion, 0) as ScenarioVersion
                           FROM 
                            PortCon..tpc_psa_scenarios scens
                            LEFT JOIN
                            PortCon..tpc_psa_scenario_items items
                            ON
                            scens.ScenarioID = items.ScenarioID and
                            scens.ModifiedOn = items.CreatedOn
                           WHERE scens.ScenarioName = CAST(? as varchar(60))""",ScenarioName)
        scen = result.fetchone()
    if not scen: raise Exception("Scenario " + ScenarioName + " does not exist")
    
    with dblock:
        for i in zip(K2_IDs, Weights):            
            result.execute("""INSERT INTO PortCon..tpc_psa_scenario_items (
                                ScenarioID,
                                ScenarioVersion,
                                k2_id,
                                weight,
                                CreatedBy,
                                CreatedOn
                                ) VALUES (
                                CAST( ? as int),
                                CAST( ? as int),
                                CAST( ? as int),
                                CAST( ? as decimal(5,2)),
                                CURRENT_USER,
                                ?
                                )""", scen.ScenarioID, scen.ScenarioVersion + 1, i[0], i[1], now)
        result.execute("""UPDATE PortCon..tpc_psa_scenarios
                            SET ModifiedBy = CURRENT_USER, ModifiedOn = ?
                            WHERE ScenarioID = CAST( ? as int)""", now, scen.ScenarioID)
        conn.commit()
    
    with watchlock:
        watchers[ScenarioName] = scen.ScenarioVersion + 1 # Tell any listeners we have a new version
        
    return scen.ScenarioVersion + 1
   
watchlock = threading.Lock()
watchers = dict() # A dictionary of Scenarios and their latest version
   
@register(return_type=int, args=(str, int))
def WatchScenario( ScenarioName, Version=0 ):
    """Watch a particular Scenario for changes beyond a specified Version. 
    This function with not return until a timeout or a new version is available. It will
    return a timeout exception or the latest Version number."""
    max_wait = 20
    interval = .5
    
    with dblock:
        result.execute("""SELECT ScenarioVersion 
                               FROM PortCon..tpc_psa_scenarios s
                                   inner join
                                   PortCon..tpc_psa_scenario_items i
                                   ON
                                   s.ScenarioID = i.ScenarioID and
                                   s.ModifiedOn = i.CreatedOn
                               WHERE
                                   s.ScenarioName = CAST(? as varchar(60))""", ScenarioName)
        latest_version = result.fetchone()
    latest_version = latest_version.ScenarioVersion
    
    watchers[ScenarioName] = latest_version
    if Version == 0 or Version is None: Version = latest_version
    
    if latest_version > Version:
        return latest_version
        
    
    
    for i in range(0,int(max_wait/interval)):
        with watchlock:
            if watchers[ScenarioName] > Version:
                print "Watch fired for",ScenarioName,"ver",watchers[ScenarioName]
                return watchers[ScenarioName]
        time.sleep(interval + random.randint(-5,5))
    raise Exception("Timeout waiting for change in Scenario "+ScenarioName)
            
psa_app = create_application(psa_server, "")
