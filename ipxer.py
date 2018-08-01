import sys
from flask import Flask, url_for
from flask import send_file
from flask_restful import Resource, Api
import dns.reversename
import dns.resolver
import ipaddress
import geoip2.database

app = Flask(__name__)
api = Api(app)

reader = geoip2.database.Reader('GeoLite2-City.mmdb')
about = {'author': '@tvldz',
         'notes': ['This product includes GeoLite2 data created by MaxMind, available from <a href="http://www.maxmind.com">http://www.maxmind.com</a>.', 'IP to ASN information provided by <a href="http://www.team-cymru.org/IP-ASN-mapping.html">Team Cymru</a>'],
         'donations': {'BTC': '3KvfwqM3DLzw4rYZt1667FHfmi3V7zSiMa',
                              'ETH': '0xD9614A0C6f74BcAf6608D1F2DF006c914bA06757',
                              'XLM': 'GCJWPDRXB64PLAGYE6D3NHYCH6KFQLNX5GWMB5BGQXHK33KPLKYRQWDE'}}


class ResolverAPI(Resource):

    def get(self, record_type, name):
        try:
            record_type = recordtype.lower()
            if record_type == 'mx':
                answers = dns.resolver.query(name, 'MX')
                return_object = []
                for rdata in answers:
                    return_object.append({'type': 'MX', 'host': str(
                        rdata.exchange), 'preference': str(rdata.preference), 'ttl': str(answers.ttl)})
                return {'rows': return_object}

            if record_type == 'a':
                answers = dns.resolver.query(name, 'A')
                return_object = []
                for rdata in answers:
                    return_object.append({'type': 'A', 'address': str(
                        rdata.address), 'ttl': str(answers.ttl)})
                return {'rows': return_object}

            if record_type == 'aaaa':
                answers = dns.resolver.query(name, 'AAAA')
                return_object = []
                for rdata in answers:
                    return_object.append({'type': 'AAAA', 'address': str(
                        rdata.address), 'ttl': str(answers.ttl)})
                return {'rows': return_object}

            if record_type == 'txt':
                answers = dns.resolver.query(name, 'TXT')
                return_object = []
                for rdata in answers:
                    for txt_string in rdata.strings:
                        return_object.append(
                            {'type': 'TXT', 'result': txt_string.decode('utf-8'), 'ttl': str(answers.ttl)})
                return {'rows': return_object}

            if record_type == 'ns':
                answers = dns.resolver.query(name, 'NS')
                return_object = []
                for rdata in answers:
                    return_object.append(
                        {'type': 'NS', 'result': str(rdata), 'ttl': str(answers.ttl)})
                return {'rows': return_object}

            if record_type == 'ptr':
                qname = dns.reversename.from_address(name)
                answers = dns.resolver.query(qname, 'PTR')
                return_object = []
                for rdata in answers:
                    return_object.append(
                        {'type': 'PTR', 'result': str(rdata), 'ttl': str(answers.ttl)})
                return {'rows': return_object}

        except (dns.resolver.NXDOMAIN):
            return {'error': "The requested domain does not exist (NXDOMAIN)"}
        except (dns.resolver.NoAnswer):
            return {'error': "The DNS response does not contain an answer to the question (NoAnswer)"}
        except (dns.exception.Timeout):
            return {'error': 'The DNS operation timed out'}
        except:
            return {'error': "Internal Server Error"}


class IpInfo(Resource):

    def get(self, ipv4_address):
        # test if valid IP address
        try:
            ip = ipaddress.ip_address(ipv4_address)
        except:
            return {'error': 'Invalid IPv4 Address'}
        if (type(ip) is ipaddress.IPv6Address):
            return {'error': 'Invalid IPv4 Address'}

        return_dict = {
            'as': '-',
            'asname': '-',
            'bgpprefix': '-',
            'registry': '-',
            'allocationdate': '-',
            'country': '-',
            'subdivision': '-',
            'city': '-'}

        lookup_host = ipaddress.ip_address(ip).reverse_pointer
        lookup_host = lookup_host.replace(
            ".in-addr.arpa", ".origin.asn.cymru.com")
        try:
            answers = dns.resolver.query(lookup_host, 'TXT')
            for rdata in answers:
                x = rdata.strings
            x = x[0].decode("utf-8").split(' | ')
            cymru_asn = x[0]
            return_dict["as"] = x[0]
            return_dict["bgpprefix"] = x[1]
            return_dict["registry"] = x[3].upper()
            return_dict["allocationdate"] = x[4]

            lookup_host = lookup_host.replace(
                ".origin.asn.cymru.com", ".asn.cymru.com")
            lookup_host = 'AS' + cymru_asn + ".asn.cymru.com"
        except Exception as e:
            pass
        try:
            answers = dns.resolver.query(lookup_host, 'TXT')
            for rdata in answers:
                x = rdata.strings
            as_list = x[0].decode("utf-8").split(' | ')
            return_dict["asname"] = as_list[4]
        except:
            pass

        # geoIP
        try:
            response = reader.city(ipv4_address)
            return_dict["country"] = response.country.name
            if (response.subdivisions.most_specific.name):
                return_dict[
                    "subdivision"] = response.subdivisions.most_specific.name
            if (response.city.name):
                return_dict["city"] = response.city.name
        except:
            pass
        return return_dict


class Root(Resource):

    def get(self):
        return send_file('static/index.html')


class Query(Resource):

    def get(self, query):
        return send_file('static/index.html')

# temp classes for serving static files


class IpxerJS(Resource):

    def get(self):
        return send_file('static/ipxer.js')


class IpxerCSS(Resource):

    def get(self):
        return send_file('static/styles.css')


api.add_resource(IpInfo, '/api/ipv4/<string:ipv4_address>')
api.add_resource(ResolverAPI, '/api/<string:record_type>/<string:name>')
api.add_resource(IpxerJS, '/static/ipxer.js')
api.add_resource(IpxerCSS, '/static/styles.css')

api.add_resource(Root, '/')
api.add_resource(Query, '/<string:query>')

if __name__ == '__main__':
    # app.run(debug=True)
    app.run(host='0.0.0.0')
