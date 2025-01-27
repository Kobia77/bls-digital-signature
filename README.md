<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>BLS-Like Signature GUI</h1>
    <p>This is a Python implementation of a simplified BLS-like signature scheme with a graphical user interface (GUI). The code demonstrates signing and verifying messages using a basic cryptographic setup.</p>

   <h2>How to Use</h2>

   <h3>1. Prerequisites</h3>
   <ul>
       <li>Ensure you have Python 3.x installed.</li>
       <li>Install the required modules (default modules like <code>tkinter</code> and <code>hashlib</code> are included with Python).</li>
   </ul>

   <h3>2. Running the Code</h3>
   <p>Save the Python script to a file, for example <code>bls_gui.py</code>. Then, execute the script in your terminal:</p>
   <pre><code>python bls_gui.py</code></pre>

   <h3>3. Using the GUI</h3>
   <ol>
       <li>When the GUI opens, you will see your <b>secret key</b> and <b>public key</b> displayed at the top.</li>
       <li>Enter a message in the "Message to Sign" field and click <b>Sign Message</b>. The signature will appear below the button.</li>
       <li>To verify, enter the same or a different message in the "Message to Verify" field and click <b>Verify Signature</b>.</li>
       <li>The verification result will appear, along with details of the verification process, such as the hash exponent, left side, and right side values.</li>
   </ol>

   <h2>Features</h2>
   <ul>
       <li>Generates a secret key and public key during initialization.</li>
       <li>Signs a message by computing a signature using the secret key.</li>
       <li>Verifies the signature against the message and public key.</li>
       <li>Displays intermediate values during verification (hash exponent, left side, and right side).</li>
       <li>Interactive GUI for user input and feedback.</li>
   </ul>

   <h2>Code Overview</h2>
   <p>The code is divided into the following sections:</p>
   <ul>
        <li><b>Cryptographic Functions:</b> Implements modular exponentiation, hashing, and pairing functions.</li>
        <li><b>Key Generation:</b> Generates a secret key and corresponding public key.</li>
        <li><b>Signing:</b> Signs a message using the secret key.</li>
        <li><b>Verification:</b> Verifies a signature by comparing computed values.</li>
        <li><b>GUI:</b> Provides an interface for signing and verifying messages.</li>
    </ul>

   <h2>Important Notes</h2>
   <ul>
       <li>This implementation is for educational purposes only and should not be used in production.</li>
       <li>It does not implement real elliptic curve operations or secure cryptographic primitives.</li>
   </ul>

   <h2>Example</h2>
   <p>Run the script and follow the steps in the GUI:</p>
   <ol>
       <li>Enter "Hello, World!" in the "Message to Sign" field and sign it.</li>
       <li>Use the same message or a modified one in the "Message to Verify" field to test verification.</li>
   </ol>

   <h2>License</h2>
   <p>Feel free to use and modify the code for learning purposes. Not for production use.</p>
    <p>Made By: Kobi Alen, Lior Engel and Matan Kahlon.</p>
</body>
</html>
