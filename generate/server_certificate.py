import os
import subprocess
import sys
import secrets

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


def create_certificate_authority(validity, ca_password, ca_server):
    """
    Create your own CA (Certificate Authority). Use openssl to generate a new CA certificate.
    :param validity: CA validity period
    :return:runs the command and returns the subprocess output
    """
    cmd = "openssl req -new -x509 -keyout ca-key -out ca-cert -days %s -passout pass:\"%s\" -subj \"/CN=%s\"" % (validity, ca_password, ca_server)
    run(cmd)


def create_private_key(node, domain, store_pass, key_pass, validity):
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
    cmd = keytool + " -genkey -keyalg RSA -keystore kafka.server.keystore.jks -storepass \"%s\" -keypass \"%s\" -validity %s -alias %s -dname CN=\"%s.%s\"" \
          % (store_pass, key_pass, validity, node, node, domain)
    run(cmd)


def extract_certificate(store_pass, key_pass, node):
    """
    Exports the certificate from the keystore created in create_private_key function
    :param store_pass:
    :param key_pass:
    :return: runs the command and returns the subprocess output
    """
    cmd = keytool + " -keystore kafka.server.keystore.jks -certreq -file cert-file -storepass \"%s\" -keypass \"%s\" -alias %s " % (store_pass, key_pass, node)
    run(cmd)


def create_trust_store(ts_password):
    """
    Add the generated CA to the clients “truststore” so that the clients can trust this CA.
    :return: runs the command and returns the subprocess output
    """
    cmd = keytool + " -keystore kafka.server.truststore.jks -storepass \"%s\" -alias CARoot -import -file ca-cert -noprompt" % ts_password
    run(cmd)


def sign_with_ca(node, ca_pass, validity):
    """
    Signing the extracted certificates with CA
    :param ca_truststore:
    :param node:
    :return: runs the command and returns the subprocess output
    """
    cmd = "openssl x509 -req -CA ca/ca-cert -CAkey ca/ca-key -in %s/cert-file -out %s/cert-signed -days %s -passin pass:\"%s\"" \
          % (node, node, validity, ca_pass)

    run(cmd)


def import_certificate(node, store_pass, key_pass):
    """
    Imports both the certificate of the CA and the signed certificate into the keystore.
    :param ca_truststore:
    :param node:
    :return: runs the command and returns the subprocess output
    """
    ca_import = keytool + " -keystore %s/kafka.server.keystore.jks -storepass \"%s\" -keypass \"%s\" -alias CARoot -import -file ca/ca-cert -noprompt" \
                % (node, store_pass, key_pass)

    run(ca_import)

    node_import = keytool + " -keystore %s/kafka.server.keystore.jks -storepass \"%s\" -keypass \"%s\" -alias %s -import -file %s/cert-signed -noprompt" \
                  % (node, store_pass, key_pass, node, node)

    run(node_import)


def scp_certificates(user, node, domain, path):
    try:
        # scp truststore and keystore
        scp_truststore = "rsync ca/* %s/kafka.server.keystore.jks %s@%s.%s:%s/ssl" % (node, user, node, domain, path)
        run(scp_truststore)
        print("SCP for node: %s\nStatus: OK" % node)
    except Exception as e:
        print("SCP for node: %s\nStatus: ERROR\nmsg: %s" % (node, e))


if __name__ == '__main__':
    validity = 365

    cluster_name = "ssl"
    nodes = input("Enter nodes (comma separated): ")
    nodes = nodes.replace(' ', '').split(',')
    domain = input("Enter domain (e.g: ekbana.com): ")
    ca_server = input("Enter CA server (give FQDN of server): ")
    user = input("Enter common username for all nodes (for scp): ")
    scp_path = input("Enter path to save certificates (for scp): ")

    # Generate Random Password for CA
    ca_password = secrets.token_urlsafe(16)
    # Generate Ramdom Password for TrustStore
    ts_password = secrets.token_urlsafe(16)
    # Generate Ramdom Password for Keystore (store)
    kss_password = secrets.token_urlsafe(16)
    # Generate Ramdom Password for Keystore (key)
    ksk_password = secrets.token_urlsafe(16)

    ca_truststore_dir = "../" + cluster_name + "/ca"

    if not os.path.exists(ca_truststore_dir):
        print("\n########################### Create a folder to store CA and Truststore ###########################\n")
        try:
            # creating a ca_truststore dir
            os.makedirs(ca_truststore_dir)
        except OSError:
            print("Creation of the directory %s failed" % ca_truststore_dir)
        else:
            print("Successfully created the directory %s" % ca_truststore_dir)

    # changing dir to ca_truststore for storing CA and Truststore
    os.chdir(ca_truststore_dir)

    print("\n########################### Create Certificate Authority (CA) ###########################\n")
    create_certificate_authority(validity, ca_password, ca_server)
    print("\n########################### Create Trust Store ###########################\n")
    create_trust_store(ts_password)

    # go back to *_cluster
    os.chdir("../")

    for node in nodes:
        # creating a node dir
        try:
            os.mkdir(node)
            # changing dir to node dir
            os.chdir(node)
            print("\n########################### Create Private Keystore ###########################\n")
            create_private_key(node, domain, kss_password, ksk_password, validity)
            print("\n########################### Export Certificate from Keystore ###########################\n")
            extract_certificate(kss_password, ksk_password, node)

            # go back to *_cluster
            os.chdir("../")
            print("\n########################### Sign the Exported Certificate with CA ###########################\n")
            sign_with_ca(node, ca_password, validity)
            print("\n########################### Re-import all the signed certificates to keystore ###########################\n")
            import_certificate(node, kss_password, ksk_password)
        except OSError:
            print("Creation of the directory %s failed" % node)

    print("\n########################### Scp certificates to given location ###########################\n")
    [scp_certificates(user, node, domain, scp_path) for node in nodes]

    print("\n########################### Removing temporary ssl dir ###########################\n")
    os.system("rm -rf ../ssl")

    print("\n\n###################################### Passwords ###################################\n\n")
    print("CA Password: %s" % ca_password)
    print("Trust Store Password: %s" % ts_password)
    print("Keystore-store Password: %s" % kss_password)
    print("Keystore-key Password: %s" % ksk_password)
    print("\n####################################################################################\n")


