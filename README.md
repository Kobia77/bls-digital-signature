<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>BLS Signature GUI</h1>
    <p>This project provides Python implementations of a BLS signature implementation, with both single and aggregate signature functionality, complete with graphical user interfaces (GUIs) for demonstration purposes.</p>

   <h2>Directory Structure</h2>
   <pre>
   └── woozai-bls-data-secure.git/
       ├── README.md
       ├── menu.py
       ├── TestsBls/
       │   ├── testingAggregateBls.py
       │   ├── testingSingleBls.py
       │   └── __pycache__/
       ├── aggregateBls/
       │   ├── aggregateBlsAlg.py
       │   ├── aggregateBlsGui.py
       │   └── __pycache__/
       └── singleBls/
           ├── singleBlsAlg.py
           ├── singleBlsGui.py
           └── __pycache__/
   </pre>

   <h2>How to Use</h2>

   <h3>1. Prerequisites</h3>
   <ul>
       <li>Ensure you have Python 3.x installed.</li>
       <li>Install any necessary modules. Default modules such as <code>tkinter</code> and <code>hashlib</code> are included with Python.</li>
   </ul>

   <h3>2. Running the Code</h3>
   <p>Use the <code>menu.py</code> script to access both single and aggregate BLS GUIs:</p>
   <pre><code>python menu.py</code></pre>

   <p>Alternatively, run each GUI individually:</p>
   <ul>
       <li>For Single BLS GUI: <code>python singleBls/singleBlsGui.py</code></li>
       <li>For Aggregate BLS GUI: <code>python aggregateBls/aggregateBlsGui.py</code></li>
   </ul>

   <h3>3. Using the GUI</h3>
   <p>Both GUIs follow similar workflows, allowing you to generate keys, sign messages, and verify signatures interactively.</p>

   <h4>Single BLS GUI</h4>
   <ol>
       <li>Upon starting, the GUI displays a generated <b>secret key</b> and <b>public key</b>.</li>
       <li>Enter a message in the "Message to Sign" field and click <b>Sign Message</b>. The signature will appear below the button.</li>
       <li>To verify, enter the message in the "Message to Verify" field and click <b>Verify Signature</b>. Verification details will appear below.</li>
   </ol>

   <h4>Aggregate BLS GUI</h4>
   <ol>
       <li>Manage multiple signers by adding signer names. Public keys for each signer will be displayed.</li>
       <li>Select a signer, input a message, and click <b>Sign Message</b> to generate a signature.</li>
       <li>Aggregate multiple signatures using the <b>Aggregate All Signatures</b> button.</li>
       <li>Optionally verify aggregated signatures, including tampered messages, using the verification section.</li>
   </ol>

   <h2>Features</h2>
   <ul>
       <li>Generates secret keys and public keys for single and aggregate signers.</li>
       <li>Signs messages using secret keys and verifies signatures with public keys.</li>
       <li>Displays intermediate values (e.g., hash exponent, pairing results) during signature verification.</li>
       <li>Interactive GUIs for user input and feedback.</li>
       <li>Aggregate BLS GUI supports multiple signers and message aggregation.</li>
   </ul>

   <h2>Code Overview</h2>
   <ul>
       <li><b>menu.py:</b> Provides a main menu to launch Single or Aggregate BLS GUIs.</li>
       <li><b>aggregateBls/:</b> Contains code for aggregate BLS functionality and GUI.</li>
       <li><b>singleBls/:</b> Contains code for single BLS functionality and GUI.</li>
       <li><b>TestsBls/:</b> Unit tests for both single and aggregate BLS implementations.</li>
   </ul>

   <h2>Important Notes</h2>
   <ul>
       <li>This implementation is for educational purposes only and should not be used in production environments.</li>
       <li>It does not implement real elliptic curve operations or secure cryptographic primitives.</li>
   </ul>

   <h2>License</h2>
   <p>Made By: Kobi Alen, Lior Engel, and Matan Kahlon.</p>
</body>
</html>
