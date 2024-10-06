import logging
import requests
import urllib3
import traceback
from functools import wraps
from datetime import datetime
import os
import sys
import json
import time
import uuid
import shutil

# ================= CONST =================
API_KEY = '4srZNTDXSGeSLksjYuaWCj7X6odXnq1NX2zHMnpETfU'
API_HOST = 'https://pttahost/api'
REP_LIST = '3704d32a-3c12-469a-b373-eafcf0c51e28'

NAME = 'data'
FILE_IN = os.path.join('in', f'{NAME}.json')
DIR_OUT = 'out'
IOC_NAME = 'data'
IOC_FORMAT = '.ioc'
LIMIT_FILE_SIZE = 3 * 1024 * 1024 # 3M

_log_format = f'%(asctime)s [%(levelname)s] (%(filename)s:%(lineno)d):[%(block_index_run)s] %(message)s'

# ================= Pre-setting =================
urllib3.disable_warnings() # disable alert ssl

app = {}

class Error:
    def __init__(self, message):
        self.message = message

class Object:
    def __init__(self, d=None):
        if d is not None:
            for key, value in d.items():
                setattr(self, key, value)

def Logger(func):
    @wraps(func)
    def wrapper(**self): 
        if 'Logger' not in app:
            app['Logger'] = logging.getLogger("convert")
            app['Logger'].setLevel(logging.INFO)
            file_handler = logging.FileHandler("convert.log", mode='w')
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(logging.Formatter(_log_format))
            stream_handler = logging.StreamHandler()
            stream_handler.setLevel(logging.INFO)
            stream_handler.setFormatter(logging.Formatter(_log_format))
            app['Logger'].addHandler(file_handler)
            app['Logger'].addHandler(stream_handler)

        block = 0 if 'block_index_run' not in self else self['block_index_run']
        extra = {'block_index_run':block}

        class Logger(logging.LoggerAdapter):
            def __init__(self, log, extra=None):
                super().__init__(log, extra)

        self['Logger'] = Logger(app['Logger'], extra=extra)
        name_block = '' if 'block_name' not in self else self['block_name']
        error = False
        try:
            self['Logger'].info(f'Start {name_block}')
            r = func(**self)
            return r
        except Exception as e:
            _, _, exc_tb = sys.exc_info()
            index = -6
            if len(traceback.extract_tb(exc_tb)) < 6:
                index = -1
            lineno = traceback.extract_tb(exc_tb)[index].lineno
            filename = os.path.basename(traceback.extract_tb(exc_tb)[index].filename)
            message = f'Called in {filename}:{lineno} with error {e}'
            self['Logger'].error(f'Error performing {name_block}. More: {message}')
            self['error'] = message
            error = True
        except KeyboardInterrupt:
            self['Logger'].critical('Signal keyboardInterrupt. Exit')
            sys.exit()
        finally:
            self['Logger'].info(f'Finish {name_block}')
        if error:
            return Error(self['error'])
            # return func(**self)
    return wrapper

def Block(f):
    @wraps(f)
    def wrapper(**self): 
        if 'block_index_run' not in app:
            app['block_index_run'] = 0
        app['block_index_run'] += 1
        self['block_index_run'] = app['block_index_run']
        self['block_name'] = f.__name__
        return f(**self)
    return wrapper

def AuthToken(f):
    """
    api GET

    /auth/token?apiKey={apiKey}
    """
    @wraps(f)
    def wrapper(**self): 
        # if 'error' in self:
        #     return f(**self)

        if 'res_auth_token' not in app:
            res = Object({
                'accessToken': None,
                'tokenType': None,
                'expiresIn': 0
            })
            app['res_auth_token'] = res
            
        aheader = {}
        self['auth_headers'] = {}

        if app['res_auth_token'].expiresIn > 60:
            self['Logger'].info('Reading an authorized token')
            aheader['Authorization'] = f'{app["res_auth_token"].tokenType} {app["res_auth_token"].accessToken}'
            self['auth_headers'] = aheader

            return f(**self)

        self['Logger'].info('Getting authentication via API key')
        params = {'apiKey': API_KEY}
        r = requests.get(f'{API_HOST}/auth/token', params=params, verify=False, timeout=3)

        if r.status_code != 200:
            raise ValueError("status code is not 200")

        res = r.json()

        # check key accessToken
        if 'accessToken' not in res:
            raise ValueError('The accessToken field was not found.')

        app['res_auth_token'].accessToken = res['accessToken']

        # check key tokenType
        if 'tokenType' not in res:
            raise ValueError('The tokenType field was not found.')

        app['res_auth_token'].tokenType = res['tokenType']

        # check key tokenType
        if 'expiresIn' not in res:
            raise ValueError('The expires_in field was not found.')

        app['res_auth_token'].expiresIn = res['expiresIn']
        self['Logger'].info(f'Method auth {app["res_auth_token"].tokenType}. Access token: {app["res_auth_token"].accessToken}')

        aheader['Authorization'] = f'{app["res_auth_token"].tokenType} {app["res_auth_token"].accessToken}'
        self['auth_headers'] = aheader

        return f(**self)

    return wrapper


@Block
@Logger
@AuthToken
def rep_list_stats(**self):
    """
    Getting statistics on the reputation list

    api GET /replists/{replistUUID}/statistic
    """
    # if 'error' in self:
    #     return Error(self['error'])

    ret = Object({
        'entityCount': 0,
        'entityTypeDistribution': [Object({
            'entityType': '',
            'count': 0
        })]
    })

    r = requests.get(f'{API_HOST}/replists/{REP_LIST}/statistic', headers=self['auth_headers'], verify=False, timeout=3)

    if r.status_code == 401:
        del app['res_auth_token']
        raise ValueError(f"status code 401. Authorization...")
    elif r.status_code != 200:
        raise ValueError(f"status code is not 200. Current {r.status_code}")
    
    res = r.json()

    # check key entityCount
    if 'entityCount' not in res:
        raise ValueError('The entityCount field was not found.')
    ret.entityCount = res['entityCount']

    # check key entityTypeDistribution
    if 'entityTypeDistribution' not in res:
        raise ValueError('The entityTypeDistribution field was not found.')
    ret.entityTypeDistribution.clear()

    for x in res['entityTypeDistribution']:
        # check key entityType
        if 'entityType' not in x:
            raise ValueError('The entityType field was not found.')
        # check key count
        if 'count' not in x:
            raise ValueError('The count field was not found.')
        ret.entityTypeDistribution.append(Object({
            'entityType': x['entityType'],
            'count': x['count']
        }))

    return ret

@Block
@Logger
@AuthToken
def entityView(**self):
    """
    Getting the view identifiers of an observable object

    api GET /entity-views
    """
    # if 'error' in self:
    #     return Error(self['error'])
    
    ret = Object({
        'PT_Feeds_view': '',
        'PTMS_view': '',
        'Cybsi_view': ''
    })

    r = requests.get(f'{API_HOST}/entity-views', headers=self['auth_headers'], verify=False, timeout=3)
    if r.status_code == 401:
        del app['res_auth_token']
        raise ValueError(f"status code 401. Authorization...")
    elif r.status_code != 200:
        raise ValueError(f"status code is not 200. Current {r.status_code}")

    
    res = r.json()

    if type(res) != list:
        raise ValueError('The res array not found.')
    
    for view in res:
        # check key uuid
        if 'uuid' not in view:
            raise ValueError('The uuid field was not found.')
        # check key name
        if 'name' not in view:
            raise ValueError('The name field was not found.')
        # case
        if view['name'] == 'PT Feeds view':
            ret.PT_Feeds_view = view['uuid']
        elif view['name'] == 'PTMS view':
            ret.PTMS_view = view['uuid']
        elif view['name'] == 'Cybsi view':
            ret.Cybsi_view = view['uuid']

    return ret

@Block
@Logger
@AuthToken
def replistsEntities(**self):
    """
    Getting objects from the reputation list

    api GET /replists/{replistUUID}/entities
    """
    # if 'error' in self:
    #     return Error(self['error'])
    
    getParams = {}
    if 'params' in self:
        getParams = self['params']

    params = {
        'cursor': getParams['cursor'] if 'cursor' in getParams else '',
        'embedObjectURL': getParams['embedObjectURL'] if 'embedObjectURL' in getParams else False,
        'limit': getParams['limit'] if 'limit' in getParams else 1000,
        'viewUUID': getParams['viewUUID'] if 'viewUUID' in getParams else ''
    }

    r = requests.get(f'{API_HOST}/replists/{REP_LIST}/entities', headers=self['auth_headers'], params=params, verify=False, timeout=3)

    if r.status_code == 401:
        del app['res_auth_token']
        raise ValueError(f"status code 401. Authorization...")
    elif r.status_code != 200:
        raise ValueError(f"status code is not 200. Current {r.status_code}")


    return Object({
        'headers': r.headers,
        'json': r.json()
    })

# IOC doc
class ioc:
    def __init__(self) -> None:
        self.doc_start_raw = ''
        self.doc_end_raw = ''
        pass
    
    def start(self, 
              root_id=str(uuid.uuid4()), 
              indicator_id=str(uuid.uuid4()),
              authored_by='IOC_api',
              authored_date=datetime.now().strftime(f"%Y-%m-%dT%H:%M:%S"),
              short_description='simple_ioc_writer_source_example2.ioc',
              description='Automatically generated IOC') -> str:
        doc = f"<?xml version='1.0' encoding='UTF-8'?>\n"
        doc += f'<OpenIOC xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://openioc.org/schemas/OpenIOC_1.1" id="{root_id}" last-modified="{authored_date}" published-date="0001-01-01T00:00:00">\n'
        doc += f'  <metadata>\n'
        doc += f'    <short_description>{short_description}</short_description>\n'
        doc += f'    <description>{description}</description>\n'
        doc += f'    <keywords/>\n'
        doc += f'    <authored_by>{authored_by}</authored_by>\n'
        doc += f'    <authored_date>{authored_date}</authored_date>\n'
        doc += f'    <links/>\n'
        doc += f'  </metadata>\n'
        doc += f'  <criteria>\n'
        doc += f'    <Indicator id="{indicator_id}" operator="OR">\n'
        self.doc_start_raw = doc
        return doc
    
    def indicator(self, _type=None, keys=dict()) -> str:
        if len(keys) == 0:
            return ''
        if _type is None:
            return ''
        if type(_type) is not str:
             return ''

        if _type != 'File':
            return ''

        elem = []
        _context_document = 'FileItem'
        for i in keys:
            if i['type'] in ['MD5Hash', 'SHA1Hash', 'SHA256Hash']:
                _content_search_item = 'Md5sum'
                if i['type'] == 'SHA1Hash':
                    _content_search_item = 'Sha1sum'
                elif i['type'] == 'SHA256Hash':
                    _content_search_item = 'Sha256sum'
                _content_search = f'{_context_document}/{_content_search_item}'
                _content_type = 'string'
                if i['type'] == 'MD5Hash':
                    _content_type = 'md5'

                _content_value = i['value']
                id = str(uuid.uuid4())
                doc = f'      <IndicatorItem id="{id}" condition="is" preserve-case="false" negate="false">\n'
                doc += f'        <Context document="{_context_document}" search="{_content_search}" type="mir"/>\n'
                doc += f'        <Content type="{_content_type}">{_content_value}</Content>\n'
                doc += f'      </IndicatorItem>\n'
                elem.append(doc)

        # compile
        if len(elem) > 0:
            # doc = f'\n    <Indicator id="{_uuid}" operator="OR">\n'
            doc = ''
            for e in elem:
                doc += e
            # doc += f'    </Indicator>'
            return doc
        return ''
    
    def end(self) -> str:
        doc = f'    </Indicator>'
        doc += f'\n  </criteria>\n'
        doc += f'  <parameters/>\n'
        doc += f'</OpenIOC>'
        self.doc_end_raw = doc
        return doc


@Block
@Logger
def convertJsonToIOC(**self):
    """
    Function for loading data into a file
    """
    doc = ioc()

    i = 1
    # ii = 0
    file_ioc = open(os.path.join(DIR_OUT, f'{IOC_NAME}-{i}{IOC_FORMAT}'), 'w')
    raw = doc.start(root_id=str(uuid.uuid4()), indicator_id=str(uuid.uuid4()))
    file_ioc.write(raw)
    b = sys.getsizeof(raw)
    raw = doc.end()
    b += sys.getsizeof(raw)
    with open(FILE_IN, 'r') as f:
        l = 0
        while (line := f.readline()):
            try:
                j = json.loads(line)

                if j['type'] != 'File':
                    continue
                
                if b > LIMIT_FILE_SIZE:
                    self['Logger'].warning('File size 3M exceeded. Creating additional file')
                    i += 1
                    b = 0
                    raw = doc.end()
                    file_ioc.write(raw)
                    file_ioc.close()
                    file_ioc = open(os.path.join(DIR_OUT, f'{IOC_NAME}-{i}{IOC_FORMAT}'), 'w')
                    b += sys.getsizeof(raw)
                    raw = doc.start(root_id=str(uuid.uuid4()), indicator_id=str(uuid.uuid4()))
                    b += sys.getsizeof(raw)
                    file_ioc.write(raw)

                ret = doc.indicator(_type=j['type'], keys=j['keys'])
                b += sys.getsizeof(ret)
                file_ioc.write(ret)
            except Exception as e:
                self['Logger'].error(e)
                continue
    
    file_ioc.write(doc.end())
    file_ioc.close()

    return None

@Block
@Logger
def main(**self):
    # Getting statistics on the reputation list
    self['Logger'].info('Getting statistics on the reputation list')
    rls = rep_list_stats()

    if type(rls) == Error:
        return exit(1)

    self['Logger'].info(f'Number of elements {rls.entityCount}')

    # Getting the view identifiers of an observable object
    self['Logger'].info('Getting the view identifiers of an observable object')
    ev = entityView()
    if type(ev) == Error:
        return exit(1)
    
    self['Logger'].info(F'View identifiers {ev.__dict__}')

    # create dir
    try:
        shutil.rmtree(_in)
    except Exception as e:
        self['Logger'].warning(f"{e}")
    try:
        shutil.rmtree(_out)
    except Exception as e:
        self['Logger'].warning(f"{e}")
    try:
        _in = os.path.dirname(os.path.abspath(FILE_IN))
        _out = os.path.abspath(DIR_OUT)
        os.makedirs(_in, exist_ok=True)
        os.makedirs(_out, exist_ok=True)
    except Exception as e:
        self['Logger'].error(f"Error: {e}")
        return

    items_added = 0
    cursor = ''

    self['Logger'].info(f'Start of conversion {rls.entityCount} elements')
    file_json = open(FILE_IN, 'w')

    test_entityCount = rls.entityCount
    while items_added < test_entityCount:
        re = replistsEntities(params={
            # 'viewUUID': ev.Cybsi_view,
            # 'embedObjectURL': 1,
            'limit': 1000,
            'cursor': cursor
        })

        if type(re) == Error:
            self['Logger'].warning(f'Error retrieving data. Retrying...')
            time.sleep(1)
            continue

        for obj in re.json:
            file_json.write(json.dumps(obj))
            file_json.write('\n')
            items_added += 1

        cursor = re.headers['X-Cursor']
        self['Logger'].info(f'Loaded in {FILE_IN} elements: {items_added}/{test_entityCount}')
    
    file_json.close()
    self['Logger'].info(f'Recording in {FILE_IN} completed successfully')

    if type(convertJsonToIOC()) == Error:
        return exit(1)

    return


# ================= RUN =================
if __name__ == '__main__':
    main()
    
