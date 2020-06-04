import os
import secrets
import subprocess

# keytool path
java_home = os.getenv("JAVA_HOME")
keytool = java_home + "/jre/bin/keytool"


def run(cmd):
    """
    Runs the given command using subprocess
    :param cmd: command to execute
    :return: subprocess output
    """
    try:
        proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
        proc.communicate()
    except subprocess.CalledProcessError as e:
        print("Error while executing command: %s" % cmd)
        print(e.stdout)


def create_trust_store(ts_password, ca_dir):
    """
    Add the generated CA to the clients “truststore” so that the clients can trust this CA.
    :return: runs the command and returns the subprocess output
    """
    cmd = keytool + " -keystore kafka.client.truststore.jks -storepass \"%s\" -alias CARoot -import -file %s/ca-cert -noprompt" % (ts_password, ca_dir)
    run(cmd)


def create_private_key(store_pass, key_pass, validity, node, client_domain):
    """
    Generates unique key and the certificate for a machine in the cluster. It stores each machines own identity.
    genkey→ Generates the public & private key pair.
    keyalg→ Specifies the algorithm to use for the key pair, either RSA or DSA.
    alias→ Specifies a unique identifying string for the key pair.
    keystore→ Specifies the name of the file where the key pair is stored. It also stores the certificate.

    Different questions will be prompted, you can just press enter for all the question
    but put you “FQDN” in “What is your first and last name?” and “[no]: yes”.

    :param node:
    :param validity: key validity period
    :return: runs the command and returns the subprocess output
    """
    cmd = keytool + " -genkey -keyalg RSA -keystore kafka.client.keystore.jks -storepass \"%s\" -keypass \"%s\" -validity %s -alias %s -dname CN=\"%s\"" \
          % (store_pass, key_pass, validity, node, client_domain)
    run(cmd)


def extract_certificate(store_pass, key_pass, node):
    """
    Exports the certificate from the keystore created in create_private_key function
    :param store_pass:
    :param key_pass:
    :return: runs the command and returns the subprocess output
    """
    cmd = keytool + " -keystore kafka.client.keystore.jks -certreq -file cert-file -storepass \"%s\" -keypass \"%s\" -alias %s " % (store_pass, key_pass, node)
    run(cmd)


def sign_with_ca(ca_path, validity, ca_pass):
    """
    Signing the extracted certificates with CA
    :param ca_truststore:
    :param node:
    :return: runs the command and returns the subprocess output
    """
    cmd = "openssl x509 -req -CA %s/ca-cert -CAkey %s/ca-key -in cert-file -out cert-signed -days %s -CAcreateserial -passin pass:\"%s\"" \
          % (ca_path, ca_path, validity, ca_pass)
    run(cmd)


def import_certificate(store_pass, node, key_pass, ca_dir):
    """
    Imports both the certificate of the CA and the signed certificate into the keystore.
    :param ca_truststore:
    :param node:
    :return: runs the command and returns the subprocess output
    """
    ca_import = keytool + " -keystore kafka.client.keystore.jks -storepass \"%s\" -keypass \"%s\" -alias CARoot -import -file %s/ca-cert -noprompt" \
                % (store_pass, key_pass, ca_dir)
    run(ca_import)

    node_import = keytool + " -keystore kafka.client.keystore.jks -storepass \"%s\" -keypass \"%s\" -alias %s -import -file cert-signed -noprompt" \
                  % (store_pass, key_pass, node)
    run(node_import)


def scp_certificates(user, client_domain, path):
    try:
        # scp Client certificate
        scp_client_cert = "rsync kafka.client.keystore.jks %s@%s:%s/ssl" % (user, client_domain, path)
        run(scp_client_cert)
        print("SCP for node: %s\nStatus: OK" % node)
    except Exception as e:
        print("SCP for node: %s\nStatus: ERROR\nmsg: %s" % (node, e))


if __name__ == '__main__':
    validity = 365

    node = input("Enter Client node: ")
    client_domain = input("Enter FQDN for client: ")
    user = input("Enter username for the node (for scp): ")
    scp_path = input("Enter path to save certificate (for scp): ")

    ca_dir = input("Enter path of CA ca-cert and ca-key: ")
    ca_pass = input("Enter CA password: ")

    # Generate Ramdom Password for Client TrustStore
    ts_pass = secrets.token_urlsafe(16)
    # Generate Ramdom Password for Client Keystore (store)
    kss_password = secrets.token_urlsafe(16)
    # Generate Ramdom Password for Client Keystore (key)
    ksk_password = secrets.token_urlsafe(16)

    try:
        os.makedirs("../client_ssl/")
        # changing dir client_ssl
        os.chdir("../client_ssl")

        print("\n########################### Create Trust Store ###########################\n")
        create_trust_store(ts_pass, ca_dir)
        print("\n########################### Create Private Keystore ###########################\n")
        create_private_key(kss_password, ksk_password, validity, node, client_domain)
        print("\n########################### Export Certificate from Keystore ###########################\n")
        extract_certificate(kss_password, ksk_password, node)

        print("\n########################### Sign the Exported Certificate with CA ###########################\n")
        sign_with_ca(ca_dir, validity, ca_pass)
        print("\n########################### Re-import all the signed certificates to keystore ###########################\n")
        import_certificate(kss_password, ksk_password, node, ca_dir)
    except OSError:
        print("Creation of the directory %s failed" % node)

    print("\n########################### Scp certificates to given location ###########################\n")
    scp_certificates(user, client_domain, scp_path)

    # print("\n########################### Removing temporary ssl dir ###########################\n")
    # os.system("rm -rf ../client_ssl")

    print("\n\n###################################### Passwords ###################################\n\n")
    print("Client Trust Store Password: %s" % ts_pass)
    print("Client Keystore-store Password: %s" % kss_password)
    print("Client Keystore-key Password: %s" % ksk_password)
    print("\n####################################################################################\n")


