from flask import Flask,request,render_template,jsonify,redirect,url_for,abort,flash
from flask_restful import Api,Resource,reqparse
from models import db,UserModel
from flask_cors import CORS,cross_origin
from flask_login import login_user,current_user,logout_user,login_required
import meraki
import meraki.exceptions

import logging
import datetime

class CustomFormatter(logging.Formatter):
    """Logging colored formatter, adapted from https://stackoverflow.com/a/56944256/3638629"""

    grey = '\x1b[38;21m'
    blue = '\x1b[38;5;39m'
    yellow = '\x1b[38;5;226m'
    red = '\x1b[38;5;196m'
    bold_red = '\x1b[31;1m'
    reset = '\x1b[0m'

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Create custom logger logging all five levels
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Define format for logs
fmt = '%(asctime)s | %(levelname)8s | %(message)s'

# Create stdout handler for logging to the console (logs all five levels)
stdout_handler = logging.StreamHandler()
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(CustomFormatter(fmt))

# Create file handler for logging to a file (logs all five levels)
today = datetime.date.today()
file_handler = logging.FileHandler('my_app_{}.log'.format(today.strftime('%Y_%m_%d')))
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter(fmt))

# Add both handlers to the logger
logger.addHandler(stdout_handler)
logger.addHandler(file_handler)

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Bitvuenetworks.db'
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['CORS_HEADERS'] = 'Content-Type'
db.init_app(app)

dashboard = meraki.DashboardAPI(api_key="8e4b670390782da578eaf98bb8ee55e86ed28f28", suppress_logging=True)

with app.app_context():
    db.create_all()

api = Api(app)

# @app.before_first_request
# def create_table():
#     db.create_all()



@app.route('/')
def hello_world():
    return render_template("index.html")


class Users(Resource):

    def get(self):
        users = UserModel.query.all()
        logger.info("Listed all Users")
        return list(x.json() for x in users)

    def post(self):
        data = request.get_json()
        user_exists = UserModel.query.filter_by(Email=data["Email"]).first()
        if user_exists:
            logger.error(f'{data["Email"]} already present.Try to register with other Email')
            return abort(404)
        if data['Role']=="Admin":
            imageURL='assets/images/Admin.png'
        else:
            imageURL='assets/images/User.png'
        new_user = UserModel(data["UserName"],data['Role'],data["Email"],data["Password"],data["Contact"],imageURL)
        db.session.add(new_user)
        db.session.commit()
        logger.info(f'{new_user} added successfully')
        db.session.flush()
        return new_user.json(),201

class NetworkPolicy(Resource):

    def post(self):
        data = (request.json)
        print(type(data))
        print(data["delay"])
        return jsonify(data)


class User(Resource):

    def get(self,id):
        user = UserModel.query.filter_by(id=id).first()
        if user:
            logger.info(f'{user} data is displayed')
            return user.json()
        else:
            logger.error(f'{user} not exist')
            return {"message":"User id not found..........."},404

    def delete(self,id):
        user = UserModel.query.filter_by(id=id).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            logger.info(f'{user} got deleted successfully')
            return {"message":"Delete Successfully"}
        else:
            logger.error(f'{user} not exist')
            return {"message":"Product id not found"},404

    def put(self,id):
        data = request.get_json()
        user = UserModel.query.filter_by(id=id).first()

        if user:
            user.UserName = data["UserName"]
            user.Role = data["Role"]
            user.Email = data["Email"]
            user.Password = data["Password"]
            user.Contact = data["Contact"]
        else:
            logger.error(f'Editing not possible for {user}')
            return {"message":"User id not present to update it"}

        db.session.add(user)
        db.session.commit()
        logger.info(f'{user} fields got edited successfully')
        return user.json()


class UserRole(Resource):
    def get(self,Email):
        user = UserModel.query.filter_by(Email=Email).first()
        if user:
            print(user)
            return user.json()
        else:
            return {"message":"User Doesn't Exist"}


class Login(Resource):

    def post(self):
        data = request.get_json()
        user = UserModel.query.filter_by(Email=data["Email"]).first()

        if user:
            if user.Password == data["Password"]:
                logger.info(f"{user.UserName}Login Successful")
                return user.json(),201
            else:
                logger.error(f"{user.UserName} Login UnSuccessful")
                flash("Entered Incorrect email or password check once",'danger')
                return abort(404)


def match_organization(organization_name):
    try:
        organization_list = dashboard.organizations.getOrganizations()
        for org_name in organization_list:
            if organization_name == org_name["name"]:
                org_id = org_name["id"]
                return org_id
    except meraki.exceptions.APIError as error:
        print(error.status, error.reason, error.message)


def match_network(organization_name, network_name):
    try:
        network_list = dashboard.organizations.getOrganizationNetworks(organizationId=match_organization(organization_name))
        for network in network_list:
            if network_name == network["name"]:
                network_id = network["id"]
                return network_id
    except meraki.exceptions.APIError as error:
        print(error.status, error.reason, error.message)


class Organizations(Resource):
    def get(self):
        OrgList=[]
        try:
            print("OrganizationList")
            List = dashboard.organizations.getOrganizations()
            for Org in List:
                OrgList.append(Org['name'])
            return OrgList
        except meraki.exceptions.APIError:
            print("404")
            return abort(404)


class Networks(Resource):

    def get(self,Org_Name):
        Network_List=[]
        try:
            NetworkList = dashboard.organizations.getOrganizationNetworks(match_organization(organization_name=Org_Name))
            for Network in NetworkList:
                Network_List.append(Network['name'])
            return Network_List

        except meraki.exceptions.APIError:
            return abort(404)


class NetworkDown(Resource):

    def get(self,OrganizationName,NetworkName):
        try:
            print("a.Injecting MX L3 Outbound Firewall Deny All Rule")
            FirewallRule = dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(networkId=match_network(OrganizationName, NetworkName),
                                                                                             rules=[{"comment": "Deny All", "policy": "Deny", "protocol": "any", "destPort": "Any", "destCidr": "Any", "srcPort": "Any","srcCidr": "Any", "syslogEnabled": "false"}])
            print(FirewallRule)
            print("Deny All Firewall Rule got successfully configured")
            return True
        except meraki.exceptions.APIError as error:
            print(error.status, error.reason, error.message)
            return False


def network_device(network_id):
    try:
        device_list = dashboard.networks.getNetworkDevices(networkId=network_id)
        networkmodel = []
        networkdevice = []
        for device in device_list:
            networkmodel.append(device['model'])
            networkdevice.append(device['serial'])

        for i in range(0, len(networkmodel)):
            if networkmodel[i][1] == "S":
                return networkdevice[i]
    except meraki.exceptions.APIError as error:
        print(error.status, error.reason, error.message)


class OfflineDevice(Resource):

    def get(self,OrganizationName,NetworkName):
        try:
            print("a.Disabling Enabled and POE fields of SwitchPort 2 of MS Switch")
            device = network_device(match_network(organization_name=OrganizationName, network_name=NetworkName))
            dashboard.switch.updateDeviceSwitchPort(serial=device, portId=2, name="Enable and POE fields Disabled", enabled=False, poeEnabled=False)
            print("Disabling Enabled and POE fields of SwitchPort 2 of MS Switch was succeeded\n")
            return True
        except meraki.exceptions.APIError as error:
            print(error.status, error.reason, error.message)
            return False


class Step1(Resource):
    def get(self,OrganizationName,NetworkName):
        try:
            print("a.Modifying SD-WAN Uplink Bandwidth Limits of WAN1 and WAN2")
            dashboard.appliance.updateNetworkApplianceTrafficShapingUplinkBandwidth(networkId=match_network(OrganizationName,NetworkName),
                                                                                    bandwidthLimits={
                                                                                        'wan1': {'limitUp': 3000,
                                                                                                 'limitDown': 3000},
                                                                                        'wan2': {'limitUp': 3000,
                                                                                        'limitDown': 3000}})
            print("WAN1 and WAN2 Uplink Bandwidth Limits has successfully modified")
            return True
        except meraki.exceptions.APIError as error:
            print(error.status, error.response, error.message)
            return False


class Step2(Resource):
    def get(self,OrganizationName,NetworkName):
        try:
            print("\nb.Modifying SD-WAN's Global Bandwidth Limit i.e Per-Client-Limit")
            dashboard.appliance.updateNetworkApplianceTrafficShaping(
                networkId=match_network(OrganizationName, NetworkName),
                globalBandwidthLimits={"limitUp": 1000,
                                       'limitDown': 1000})

            print("SD-WAN's Global Bandwidth Limit i.e Per-Client-Limit has successfully modified")
            return True
        except meraki.exceptions.APIError as error:
            print(error.status, error.response, error.message)
            return False


def get_ssid_number(network_name):
    try:
        ssid_list = dashboard.wireless.getNetworkWirelessSsids(networkId=network_name)
        for SSID in ssid_list:
            if SSID['name'] == 'Corporate' or 'corporate':       # if SSID['name'] == 'ECMS1 - wireless WiFi':
                return SSID['number']
    except meraki.exceptions.APIError as error:
        print(error.status, error.response, error.message)
        return False


class Step3(Resource):
    def get(self, OrganizationName, NetworkName):
        try:
            print("\nc.Modifying Wireless Corporate SSID's Per Client Bandwidth Limit to 5Mbps")
            ssid_number = get_ssid_number(network_name=match_network(OrganizationName, NetworkName))
            dashboard.wireless.updateNetworkWirelessSsid(networkId=match_network(OrganizationName, NetworkName),
                                                         number=ssid_number,
                                                         perClientBandwidthLimitUp=20,
                                                         perClientBandwidthLimitDown=20)
            print("Wireless Per Client Bandwidth Limit has successfully modified")
            return True
        except meraki.exceptions.APIError as error:
            print(error.status, error.response, error.message)
            return False


class WirelessReconfiguration(Resource):
    def get(self,OrganizationName,NetworkName):
        try:
            print("a. Modifying Allowed Vlan's field of Switch Port 1 for denying VLAN 10 ")
            device = network_device(match_network(organization_name=OrganizationName, network_name=NetworkName))
            dashboard.switch.updateDeviceSwitchPort(serial=device, portId=1, allowedVlans="1-9,11-1028")
            print("Allowed Vlan's field got successfully modified")
            return True
        except meraki.exceptions.APIError as error:
            print(error.status,error.message)
            return False


def network_name(organization_name,network_id):
    try:
        network_list = dashboard.organizations.getOrganizationNetworks(organizationId=match_organization(organization_name))
        for network in network_list:
            if network_id == network["id"]:
                network_name = network["name"]
                return network_name
    except meraki.exceptions.APIError as error:
        print(error.status, error.reason, error.message)


class DeviceStatus(Resource):
    def get(self,OrganizationName,NetworkName):
        try:
            List = dashboard.organizations.getOrganizationDevicesStatuses(match_organization(OrganizationName))
            OfflineList=[]
            OfflineStatus=[]
            for device in List:
                if device['status']=='offline' or device['status']=='dormant':
                    if NetworkName in network_name(OrganizationName,device["networkId"]):
                       GetNetworkName = network_name(OrganizationName,device["networkId"])
                       print(f'{device["serial"]} linked with {GetNetworkName} isy {device["status"]}')
                       OfflineList.extend([[device['serial'],device['status']]])
            print(OfflineList)
            return OfflineList

        except meraki.exceptions.APIError as error:
            print(error.status, error.reason, error.message)



api.add_resource(Users,'/users')
api.add_resource(User,'/user/<int:id>')
api.add_resource(UserRole,'/user/<string:Email>')
api.add_resource(Login,'/login')
api.add_resource(Organizations,'/Organizations')
api.add_resource(Networks,'/Networks/<string:Org_Name>')
api.add_resource(NetworkDown,'/meraki/<string:OrganizationName>/<string:NetworkName>/NetworkDown')
api.add_resource(OfflineDevice,'/meraki/<string:OrganizationName>/<string:NetworkName>/OfflineDevice')

api.add_resource(Step1,'/meraki/<string:OrganizationName>/<string:NetworkName>/Step1')
api.add_resource(Step2,'/meraki/<string:OrganizationName>/<string:NetworkName>/Step2')
api.add_resource(Step3,'/meraki/<string:OrganizationName>/<string:NetworkName>/Step3')
api.add_resource(WirelessReconfiguration,'/meraki/<string:OrganizationName>/<string:NetworkName>/WirelessReconfiguration')
api.add_resource(DeviceStatus,'/meraki/<string:OrganizationName>/<string:NetworkName>/DeviceStatus')

api.add_resource(NetworkPolicy,'/parameters')
if __name__ == "__main__":
    app.run(debug=True)