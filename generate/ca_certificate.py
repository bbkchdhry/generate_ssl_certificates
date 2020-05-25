import os
import subprocess
import sys

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


def create_certificate_authority(validity):
    """
    Create your own CA (Certificate Authority). Use openssl to generate a new CA certificate.
    :param validity: CA validity period
    :return:runs the command and returns the subprocess output
    """
    cmd = "openssl req -new -x509 -keyout ca.key -out ca.csr -days %s" % validity
    run(cmd)


def create_private_key(node, validity):
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
    cmd = keytool + " -genkey -keyalg RSA -alias %s -keypass Kpassword -keystore keystore.jks -storepass Spassword -validity %s" % (node, validity)
    run(cmd)


def extract_certificate(node):
    """
    Exports the certificate from the keystore created in create_private_key function
    :param node:
    :return: runs the command and returns the subprocess output
    """
    cmd = keytool + " -keystore keystore.jks -storepass Spassword -keypass Kpassword -alias %s -certreq -file %s.csr" % (node, node)
    run(cmd)


def create_trust_store():
    """
    Add the generated CA to the clients “truststore” so that the clients can trust this CA.
    :return: runs the command and returns the subprocess output
    """
    cmd = keytool + " -keystore truststore.jks -storepass Tpassword -alias CARoot -import -file ca.csr"
    run(cmd)


def sign_with_ca(ca_truststore, node):
    """
    Signing the extracted certificates with CA
    :param ca_truststore:
    :param node:
    :return: runs the command and returns the subprocess output
    """
    cmd = "openssl x509 -req -CA %s/ca.csr -CAkey %s/ca.key -in %s/%s.csr -out %s/%s_sgn.csr -days 365 -CAcreateserial -passin pass:Cpassword" \
          % (ca_truststore, ca_truststore, node, node, node, node)

    print(os.getcwd())
    print("cmd: " + cmd)
    run(cmd)


def import_certificate(ca_truststore, node):
    """
    Imports both the certificate of the CA and the signed certificate into the keystore.
    :param ca_truststore:
    :param node:
    :return: runs the command and returns the subprocess output
    """
    ca_import = keytool + " -keystore %s/keystore.jks -storepass Spassword -alias CARoot -import -file %s/ca.csr" % (node, ca_truststore)
    print(os.getcwd())
    print("cmd: " + ca_import)
    run(ca_import)

    node_import = keytool + " -keystore %s/keystore.jks -storepass Spassword -keypass Kpassword -alias %s -import -file %s/%s_sgn.csr" % (node, node, node, node)
    print(os.getcwd())
    print("cmd: " + node_import)
    run(node_import)


if __name__ == '__main__':
    validity = 365

    cluster_name = "ssl_keys"
    nodes = input("Enter nodes (comma separated): ")
    nodes = nodes.replace(' ', '').split(',')

    ca_truststore_dir = "../" + cluster_name + "/ca_truststore"

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
    create_certificate_authority(validity)
    print("\n########################### Create Trust Store ###########################\n")
    create_trust_store()

    # go back to *_cluster
    os.chdir("../")

    for node in nodes:
        # creating a node dir
        try:
            os.mkdir(node)
            # changing dir to node dir
            os.chdir(node)
            print("\n########################### Create Private Keystore ###########################\n")
            create_private_key(node, validity)
            print("\n########################### Export Certificate from Keystore ###########################\n")
            extract_certificate(node)

            # go back to *_cluster
            os.chdir("../")
            print("\n########################### Sign the Exported Certificate with CA ###########################\n")
            sign_with_ca("ca_truststore", node)
            print("\n########################### Re-import all the signed certificates to keystore ###########################\n")
            import_certificate("ca_truststore", node)
        except OSError:
            print("Creation of the directory %s failed" % node)


