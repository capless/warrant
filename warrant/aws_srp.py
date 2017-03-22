import base64
import binascii
import datetime
import hashlib
import hmac

import os
import six


# https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
n_hex = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' + '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' + \
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' + 'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' + \
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' + 'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' + \
        '83655D23DCA3AD961C62F356208552BB9ED529077096966D' + '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' + \
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' + 'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' + \
        '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' + 'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' + \
        'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' + 'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' + \
        'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' + '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF'
# https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
g_hex = '2'
infoBits = bytearray('Caldera Derived Key', 'utf-8')


def hash_sha256(buf):
    """AuthenticationHelper.hash"""
    a = hashlib.sha256(buf).hexdigest()
    return (64 - len(a)) * '0' + a


def hexHash(hexStr):
    return hash_sha256(bytearray.fromhex(hexStr))


def hex_to_long(hex_string):
    return int(hex_string, 16)


def long_to_hex(long_num):
    return '%x' % long_num


def get_random(nbytes):
    random_hex = binascii.hexlify(os.urandom(nbytes))
    return hex_to_long(random_hex)


def padHex(bigInt):
    """
    Converts a Long integer (or hex string) to hex format padded with zeroes for hashing
    :param {Long integer|String} bigInt Number or string to pad.
    :return {String} Padded hex string.
    """
    if not isinstance(bigInt, six.string_types):
        hashStr = long_to_hex(bigInt)
    else:
        hashStr = bigInt
    if len(hashStr) % 2 == 1:
        hashStr = '0%s' % hashStr
    elif hashStr[0] in '89ABCDEFabcdef':
        hashStr = '00%s' % hashStr
    return hashStr


def computehkdf(ikm, salt):
    """
    Standard hkdf algorithm
    :param {Buffer} ikm Input key material.
    :param {Buffer} salt Salt value.
    :return {Buffer} Strong key material.
    @private
    """
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    infoBitsUpdate = infoBits + bytearray(chr(1), 'utf-8')
    hmac_hash = hmac.new(prk, infoBitsUpdate, hashlib.sha256).digest()
    return hmac_hash[:16]


def calculateU(A, B):
    """
    Calculate the client's value U which is the hash of A and B
    :param {Long integer} A Large A value.
    :param {Long integer} B Server B value.
    :return {Long integer} Computed U value.
    """
    UHexHash = hexHash(padHex(A) + padHex(B))
    finalU = hex_to_long(UHexHash)
    return finalU


class AwsSrp:

    def __init__(self, username, password, pool_id):
        self.username = username
        self.password = password
        self.pool_id = pool_id
        self.N = hex_to_long(n_hex)
        self.g = hex_to_long(g_hex)
        self.k = hex_to_long(hexHash('00' + n_hex + '0' + g_hex))
        self.smallAValue = self.generateRandomSmallA()
        self.largeAValue = self.calculateA()

    def generateRandomSmallA(self):
        """
        helper function to generate a random big integer
        :return {Long integer} a random value.
        """
        randomBigInt = get_random(128)
        smallABigInt = randomBigInt % self.N
        return smallABigInt

    def calculateA(self):
        """
        Calculate the client's public value A = g^a%N
        with the generated random number a
        :param {Long integer} a Randomly generated small A.
        :return {Long integer} Computed large A.
        """
        A = pow(self.g, self.smallAValue, self.N)
        # safety check
        if (A % self.N) == 0:
            raise ValueError('Safety check for A failed')
        return A

    def getPasswordAuthenticationKey(self, username, password, serverBValue, salt):
        """
        Calculates the final hkdf based on computed S value, and computed U value and the key
        :param {String} username Username.
        :param {String} password Password.
        :param {Long integer} serverBValue Server B value.
        :param {Long integer} salt Generated salt.
        :return {Buffer} Computed HKDF value.
        """
        UValue = calculateU(self.largeAValue, serverBValue)
        if UValue == 0:
            raise ValueError('U cannot be zero.')
        usernamePassword = '%s%s:%s' % (self.pool_id.split('_')[1], username, password)
        usernamePasswordHash = hash_sha256(usernamePassword.encode('utf-8'))

        xValue = hex_to_long(hexHash(padHex(salt) + usernamePasswordHash))
        gModPowXN = pow(self.g, xValue, self.N)
        intValue2 = serverBValue - self.k * gModPowXN
        sValue = pow(intValue2, self.smallAValue + UValue * xValue, self.N)
        hkdf = computehkdf(bytearray.fromhex(padHex(sValue)),
                           bytearray.fromhex(padHex(long_to_hex(UValue))))
        return hkdf

    def get_auth_params(self):
        return {'USERNAME': self.username,
                'SRP_A': long_to_hex(self.largeAValue)
                }

    def process_challenge(self, challenge_parameters):
        user_id_for_srp = challenge_parameters['USER_ID_FOR_SRP']
        salt_hex = challenge_parameters['SALT']
        srp_b_hex = challenge_parameters['SRP_B']
        secret_block_b64 = challenge_parameters['SECRET_BLOCK']
        timestamp = datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y")
        hkdf = self.getPasswordAuthenticationKey(user_id_for_srp, self.password, hex_to_long(srp_b_hex), salt_hex)
        secret_block_bytes = base64.standard_b64decode(secret_block_b64)
        msg = bytearray(self.pool_id.split('_')[1], 'utf-8') + bytearray(user_id_for_srp, 'utf-8') + \
              bytearray(secret_block_bytes) + bytearray(timestamp, 'utf-8')
        hmac_obj = hmac.new(hkdf, msg, digestmod=hashlib.sha256)
        signatureString = base64.standard_b64encode(hmac_obj.digest())

        return {
                "TIMESTAMP": timestamp,
                "USERNAME": user_id_for_srp,
                "PASSWORD_CLAIM_SECRET_BLOCK": secret_block_b64,
                "PASSWORD_CLAIM_SIGNATURE": signatureString.decode('utf-8')
                }
