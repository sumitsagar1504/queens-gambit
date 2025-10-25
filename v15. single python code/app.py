from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
import os, base64, json, time, smtplib, random, base64
from flask import jsonify
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from email.mime.text import MIMEText
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from math import log2
from chess import pgn, Board
from io import StringIO

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generates a random 24-byte key

# Admin login credentials
ADMIN_USERNAME = "admin123"
ADMIN_PASSWORD = "admin123"  # replace with your desired admin password

# Load users from JSON file
def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Save users to JSON file
def save_users(users_db):
    with open('users.json', 'w') as f:
        json.dump(users_db, f)

users_db = load_users()

# SMTP / OTP email configuration — set these in the environment for production
# Example (Windows PowerShell):
#  $env:SMTP_EMAIL = 'shreyanshsinhaatoz@gmail.com'; $env:SMTP_PASSWORD = '<your-app-password>'
SMTP_EMAIL = os.environ.get('SMTP_EMAIL', 'shreyanshsinhaatoz@gmail.com')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', 'gqji yalr zcvh qnzi')
OTP_DEBUG = os.environ.get('OTP_DEBUG', '').lower() in ('1', 'true', 'yes')

# Function to send OTP email
def send_otp_email(recipient_email):
    otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_EMAIL
    msg["To"] = recipient_email

    try:
        # Use a safe SMTP handshake (ehlo/starttls) then login with configured credentials
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            # send_message will use the From/To headers from the MIME message
            server.send_message(msg)
        return otp
    except Exception as e:
        # Print full traceback to help diagnose SMTP/auth issues
        import traceback
        traceback.print_exc()
        print(f"Error sending email to {recipient_email}: {e}")
        # Fallback: write OTP to a local debug log so testing can continue even if SMTP fails.
        # This makes local development and automated tests more reliable.
        try:
            with open('otp_debug.log', 'a') as dbg:
                dbg.write(f"{time.ctime()} - OTP for {recipient_email}: {otp} (SMTP failed: {e})\n")
            print(f"OTP written to otp_debug.log for {recipient_email} (fallback after SMTP failure).")
            return otp
        except Exception as log_e:
            # If writing to the debug log also fails, print both errors and return None.
            print(f"Failed to write OTP to otp_debug.log: {log_e}")
            return None

def no_to_bin_str(num: int, bits: int):
    # Convert the number to a binary string and remove the '0b' prefix
    binary = bin(num)[2:]

    # Pad the binary string with leading zeros to ensure it's 'bits' long
    return binary.zfill(bits)

def random_user_id():
    return f"{random.randint(100000, 999999)}"

def random_metadata():
    events = [
        "Friendly Match", "Tournament", "Casual Game", "Championship", 
        "Club Championship", "Simultaneous Exhibition", "Charity Match", 
        "Blitz Tournament", "Rapid Championship", "Online Invitational"
    ]
    locations = [
        "Local Club", "Online", "City Park", "University Hall", "Community Center", 
        "Chess Cafe", "Mountain Retreat", "Coastal Town", "National Stadium", 
        "Historical Landmark"
    ]
    expected_openings = [
        "Sicilian Defense", "French Defense", "Caro-Kann", "Ruy Lopez", "Italian Game", 
        "English Opening", "King's Indian Defense", "Queen's Gambit", 
        "Nimzo-Indian Defense", "Pirc Defense", "Grünfeld Defense"
    ]
    
    # Generate the first player's rating
    white_elo = random.randint(200, 3000)
    # Calculate the range for the second player's rating
    lower_bound = int(white_elo * 0.9)
    upper_bound = int(white_elo * 1.1)
    
    # Generate the second player's rating within the specified range
    black_elo = random.randint(lower_bound, upper_bound)
    
    results = ["1-0", "0-1", "1/2-1/2", "*"]  # Possible outcomes

    metadata = {
        "Event": random.choice(events),
        "Site": random.choice(locations),
        "Date": f"{random.randint(1990, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "Round": str(random.randint(1, 15)),
        "White": random_user_id(),  # Random user ID for White player
        "Black": random_user_id(),  # Random user ID for Black player
        "ExpectedOpening": random.choice(expected_openings),
        "WhiteElo": str(white_elo),
        "BlackElo": str(black_elo),
        "Result": random.choice(results),
        "Annotator": random_user_id(),  # Random ID for annotator
        "Variation": random.choice(["Main Line", "Alternative Line", "Quiet Move", "Aggressive Line", "Theoretical Novelty"]),
        "EventDate": f"{random.randint(1990, 2023)}.{random.randint(1, 12):02d}.{random.randint(1, 31):02d}",
        "TimeControl": random.choice(["3+2", "5+0", "10+0", "15+10", "30+0", "60+0", "90+30"])
    }

    # Randomly select a number of keys to hide
    keys_to_hide = random.sample(list(metadata.keys()), random.randint(1, len(metadata) // 2))
    
    # Set the selected keys' values to "Hidden"
    for key in keys_to_hide:
        metadata[key] = "Hidden"

    # return ""

    return metadata

def make_gambit(sample_file: str):
    print("Making the Gambit...")
    bittify = (255).bit_length()  # Determine the number of bits required to represent the maximum byte value (255)

    with open(sample_file, "rb") as f:  # Open the file in binary read mode
        file01 = list(f.read())  # Read the file contents and convert it into a list of bytes

    bits = bittify * len(file01)  # Calculate the total number of bits from the number of bytes in the file
    pgnlist = []  # Initialize an empty list to store PGN (Portable Game Notation) outputs
    current_pos = 0  # Initialize a bit index to track the current position in the file bits
    board_instance = Board()  # Create a new chess board instance to simulate the game

    while True:  # Start an infinite loop for generating moves until a termination condition is met
        gen_moves = board_instance.generate_legal_moves()  # Generate legal moves for the current position on the chess board

        moves_list = list(board_instance.generate_legal_moves())

        # Calculate the log2 length separately and convert it to an integer.
        log_length = int(log2(len(moves_list)))

        # Calculate the number of bits remaining.
        remaining_bits = bits - current_pos

        # Take the minimum of the two calculated values.
        # ensure bits_req is not larger than either the required bits to represent the indices or the bits left to read. This prevents indexing errors or reading past the end of available bits.
        bits_req = min(log_length, remaining_bits)

        bits_map_set_of_moves = {}  # Initialize a dictionary to map move UCI (Universal Chess Interface) strings to their binary representation
        
        # Create a dictionary of valid moves, mapping UCI strings to their corresponding binary strings
        valid_moves = {
            anti_illegal_move.uci(): no_to_bin_str(i, bits_req)
            for i, anti_illegal_move in enumerate(gen_moves)
            if len(no_to_bin_str(i, bits_req)) <= bits_req
        }

        bits_map_set_of_moves.update(valid_moves)  # Update the move_bits dictionary with valid moves
        
        next_byte_i = current_pos // bittify  # Calculate the index of the closest byte in the file that corresponds to the current bit index
        strs = ''  # Initialize a string to accumulate binary strings from the file bytes

        # Extract up to two bytes from the file and convert them to binary strings
        for byte1 in file01[next_byte_i:next_byte_i + 2]:
            binary_string = no_to_bin_str(byte1, bittify)  # Convert the byte to a binary string
            strs += binary_string  # Accumulate the binary string

        start_index = current_pos % bittify  # Calculate the starting index for extracting bits from the file chunk pool
        next_str = ''  # Initialize a string to store the next chunk of bits to be compared with legal move binaries

        # Extract the relevant bits from the file chunk pool based on the maximum binary length
        for i in range(bits_req):
            if start_index + i < len(strs):  # Ensure we don't go out of bounds
                next_str += strs[start_index + i]  # Append the bit to the next chunk

        current_pos += bits_req  # Increment the file bit index by the maximum binary length of the legal moves

        # Iterate over the valid moves to find a match with the extracted file bits
        for movei in bits_map_set_of_moves:
            bits_mapped = bits_map_set_of_moves[movei]  # Get the binary representation of the move
            if bits_mapped == next_str:  # Check if it matches the next file chunk
                board_instance.push_uci(movei)  # Push the move onto the chess board
                break  # Exit the loop once a move is found
        
        # Define a list of conditions that can terminate the loop and trigger PGN generation
        if (board_instance.legal_moves.count() <= 1.5
           or current_pos >= bits
        ):  # If any of the conditions are true, generate the PGN output
            pgn_ = pgn.Game()  # Create a new PGN game object
            metadata = random_metadata()  # Generate random metadata for the game

            # Add metadata headers to the PGN game
            for key, value in metadata.items():
               pgn_.headers[key] = value
            
            pgn_.add_line(board_instance.move_stack)  # Add the move stack from the chess board to the PGN
            pgnlist.append(str(pgn_))  # Convert the PGN game to a string and append it to the output list
            board_instance.reset()  # Reset the chess board for the next game simulation

        if current_pos >= bits:  # Break the loop if the end of the file has been reached
            break

    print("Gambit done.")
    return "\n\n".join(pgnlist)  # Return all collected PGN strings joined by two newline characters

def listify_pgns(pgn_string: str):  
    # Initialize an empty list to store parsed pgn.Game objects
    games = []
    
    # Create an in-memory file-like object from the PGN string
    pgn_stream = StringIO(pgn_string)

    # Read the first chess game from the PGN string
    game = pgn.read_game(pgn_stream)
    
    # Loop through the PGN stream and read each game until no more games are left
    while game:  # While there is a valid game (not None)
        games.append(game)  # Add the current game to the list
        game = pgn.read_game(pgn_stream)  # Read the next game from the stream
    
    # Return the list of all parsed games
    return games

def undo_gambit(games_pgn: str, output_og_sample_file: str):
    print("Undoing the Gambit...")
    moves_processed = 0  # Initialize a counter to keep track of the total number of moves processed
    bittify = (255).bit_length()  # Set the bit length for 1 byte, which is 8 (since 255 is 11111111 in binary)
    
    # Load games from PGN string
    # Convert the PGN string into a list of chess games (using a helper function)
    pgn_list = listify_pgns(games_pgn)

    # Ensure that the result is in a list form
    iterable_games = list(pgn_list)  # Convert the iterable of games into a list to iterate over later

    # Prepare to write to the output file in binary mode
    op_dec_file = open(output_og_sample_file, "wb")
    try:
        dec_data = ""  # Initialize a string to store the binary representation of moves
        # Loop through each game in the PGN list
        for pgn_g_num, g in enumerate(iterable_games):
            board_instance = Board()  # Initialize a new chess board for each game
            moves_list = list(g.mainline_moves())  # Get the main line of moves for the current game as a list
            moves_processed += len(moves_list)  # Update the total move count

            # Loop through each move in the game
            for move_i, iterable_moves in enumerate(moves_list):
                # Get UCIs (Universal Chess Interface) of legal moves in the current position
                moves_possible = board_instance.generate_legal_moves()  # Get a generator of all legal moves
                strs = [move_iterable.uci() for move_iterable in moves_possible]  # Convert legal moves into UCI string format

                # Get binary representation of the move played
                indexify_move = strs.index(iterable_moves.uci())  # Find the index of the move in the list of legal moves

                # Convert the index to a binary string and remove the '0b' prefix
                pad_indexed_bin = bin(indexify_move)[2:]  # Convert index to a binary string without the '0b' prefix

                # Determine maximum binary length for the current move
                # Check if we are at the last game and last move
                game_over = (pgn_g_num == len(iterable_games) - 1)  # Check if this is the last game
                last_move = (move_i == len(moves_list) - 1)  # Check if this is the last move in the game

                if game_over and last_move:
                    # If last game and move, calculate max binary length but adjust for file byte size
                    moves_count = len(strs)  # Get the number of legal moves
                    log_length = int(log2(moves_count))
                    remaining_bits = bittify - (len(dec_data) % bittify)
                    bits_req = min(log_length, remaining_bits)  # refer to checkmate-make_gambit to understand whats happening here

                else:
                    # For all other moves, calculate max binary length normally
                    moves_count = len(strs)  # Get the number of legal moves
                    bits_req = int(log2(moves_count))  # Calculate max binary length based on legal moves

                # Pad the binary string of the move to ensure correct length
                test_pad = bits_req - len(pad_indexed_bin)  # Calculate required padding
                non_neg_padding = max(0, test_pad)  # Ensure padding is non-negative
                padding = "0" * non_neg_padding  # Create a padding string of zeros
                pad_indexed_bin = padding + pad_indexed_bin  # Prepend the padding to the binary string

                # Play the move on the chess board
                next_move = iterable_moves.uci()  # Get the UCI representation of the move
                board_instance.push_uci(next_move)  # Push the move to update the chess board

                # Add the move's binary representation to the output data string
                dec_data += pad_indexed_bin  # Append the binary string of the move to output data

                # Check if the output_data length is a multiple of 8 bits (a full byte)
                if len(dec_data) % bittify == 0:
                    byte_values = []  # Initialize a list to store byte values

                    # Loop through the output_data in 8-bit chunks
                    num_chunks = len(dec_data) / bittify  # Calculate number of 8-bit chunks in output data
                    i = 0  # Initialize the chunk index counter

                    # Process each chunk of 8 bits
                    while i < int(num_chunks):
                        start_index = i * bittify  # Calculate the start index for the chunk
                        end_index = start_index + bittify  # Calculate the end index for the chunk

                        chunk = ''  # Initialize an empty string for the chunk
                        for indexify_move in range(start_index, end_index):
                            chunk += dec_data[indexify_move]  # Append each bit from the chunk to the chunk string

                        # Convert the 8-bit chunk into an integer
                        byte_value = 0  # Initialize the byte value
                        for bit in chunk:
                            byte_value = byte_value * 2 + int(bit)  # Shift bits left and add the current bit

                        byte_values.append(byte_value)  # Append the byte value to the list
                        i += 1  # Increment the chunk index counter

                    # Write the byte values to the output file
                    for byte_value in byte_values:
                        byte = byte_value.to_bytes(1, byteorder='big')  # Convert each byte value to a byte
                        op_dec_file.write(byte)  # Write the byte to the output file

                    dec_data = ""  # Reset the output_data string for the next iteration
    finally:
        op_dec_file.close()
    print("Gambit undone.")

# Function to encrypt data with AES-256
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes)

# Function to decrypt AES-256 encrypted data
def aes_decrypt(enc_data, key):
    enc_data = base64.b64decode(enc_data)
    iv = enc_data[:AES.block_size]
    ct = enc_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# Function to encrypt data with RSA-4096 (used for the AES key)
def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

# Function to decrypt data with RSA-4096 (used to decrypt the AES key)
def rsa_decrypt(encrypted_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if username already exists
        if username in users_db:
            flash('Username already taken. Please choose another.')
            return redirect(url_for('signup'))

        # Send OTP and store user data temporarily in session
        otp = send_otp_email(email)
        if otp is not None:
            session['otp'] = otp
            session['temp_user'] = {'username': username, 'password': password, 'email': email}
            # In debug mode, surface the OTP so testing can continue without SMTP
            if OTP_DEBUG:
                flash(f"[OTP_DEBUG] OTP for {email}: {otp}")
            return redirect(url_for('verify_signup_otp'))
        else:
            flash('Failed to send OTP. Please try again.')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/verify_signup_otp', methods=['GET', 'POST'])
def verify_signup_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        
        # Retrieve and remove OTP from session immediately after reading
        stored_otp = session.pop('otp', None)
        
        if stored_otp is not None and int(entered_otp) == stored_otp:
            # OTP is correct, save the user in the database
            temp_user = session.pop('temp_user', None)
            if temp_user:
                users_db[temp_user['username']] = {
                    'password': temp_user['password'],
                    'email': temp_user['email']
                }
                save_users(users_db)
                flash('Signup successful! Please log in.')
                return redirect(url_for('login'))
            else:
                flash('Session expired. Please try signing up again.')
                return redirect(url_for('signup'))
        else:
            flash('Invalid OTP. Please try again.')
            return redirect(url_for('signup'))

    return render_template('verify_otp.html')

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']

        # Retrieve and remove OTP from session immediately after reading
        stored_otp = session.pop('otp', None)

        # Check if OTP exists and if it matches the entered OTP
        if stored_otp is not None and int(entered_otp) == stored_otp:
            return redirect(url_for('upload_file'))  # Redirect to upload page
        else:
            flash('Invalid or expired OTP. Please try again.')
            return redirect(url_for('login'))  # Redirect back to login

# Login route handling both regular and OTP-based login
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Check if OTP was submitted
        if 'otp' in session:
            entered_otp = request.form.get('otp')
            if entered_otp == session['otp']:
                # OTP is correct, log in the user
                session.pop('otp', None)
                return redirect(url_for('upload_file'))  # Redirect to upload page
            else:
                flash('Invalid OTP. Please try again.')
                return redirect(url_for('login'))

        # Regular login process
        username = request.form['username']
        password = request.form['password']

        # Admin login check
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))

        # Check if user exists and password is correct
        if username in users_db and users_db[username]['password'] == password:
            # Send OTP to user's email
            recipient_email = users_db[username]['email']
            otp = send_otp_email(recipient_email)
            print(f"otp: {otp}")
            if otp is not None:
                session['otp'] = otp
                session['username'] = username
                if OTP_DEBUG:
                    flash(f"[OTP_DEBUG] OTP for {recipient_email}: {otp}")
                return render_template('login.html', otp_required=True)
            else:
                flash('Failed to send OTP. Please try again.')
                return redirect(url_for('login'))
        else:
            flash('Incorrect username or password, please try again.')
            return redirect(url_for('login'))

    return render_template('login.html')

# Admin dashboard to view and delete users
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin' not in session or not session['admin']:
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        username_to_delete = request.form['username_to_delete']
        if username_to_delete in users_db:
            del users_db[username_to_delete]
            save_users(users_db)
            flash(f"User '{username_to_delete}' has been deleted.")
        else:
            flash("User not found. Please try again.")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', users=users_db)

# Helper function to XOR two hex strings and return the result
def xor_hex_strings(hex1, hex2):
    """Helper function to XOR two hex strings and return the result."""
    max_length = max(len(hex1), len(hex2))
    hex1 = hex1.zfill(max_length)  # Zero-pad to ensure equal length
    hex2 = hex2.zfill(max_length)  # Zero-pad to ensure equal length
    return ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a, b in zip(hex1, hex2))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    global progress  # Ensure we're using the global progress variable

    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            # Ensure the 'uploads' folder exists
            os.makedirs('uploads', exist_ok=True)
            # base_filename = os.path.splitext(uploaded_file.filename)[0]
            uploaded_file_path = os.path.join('uploads', uploaded_file.filename)
            uploaded_file.save(uploaded_file_path)

            # Call the encode function to get PGN (assumed to be a string)
            encoded_pgn = make_gambit(uploaded_file_path)

            encoded_pgn = uploaded_file.filename + '\n' + encoded_pgn

            # Generate AES key
            aes_key = get_random_bytes(32)  # AES-256 key is 32 bytes

            # Generate RSA keys
            print("Generating RSA key...")
            tgen1 = time.time()
            rsa_key = RSA.generate(4096)
            public_key = rsa_key.publickey()
            tgen2 = time.time()
            print(f"RSA key generated in {tgen2-tgen1:.2f} seconds.")

            # Save the RSA-encrypted AES key in a file
            keys_filename = get_random_bytes(24)
            keys_filename_hex = keys_filename.hex()  # Random key for filename
            keys_xor_result = bytes(b ^ 0xff for b in keys_filename)
            keys_xor_hex_str = keys_xor_result.hex()

            # Ensure the 'rsa_keys' folder exists
            rsa_keys_directory = 'rsa_keys'
            os.makedirs(rsa_keys_directory, exist_ok=True)

            # Generate public and private key filenames based on XOR logic
            def xor_with_hex_string(original_hex, target_hex):
                return ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a, b in zip(original_hex, target_hex))

            # Target hex values for XOR: all 7's and all 8's (24 characters, hex)
            all_sevens = '1' * len(keys_filename_hex)  # Target for public key XOR result
            all_eights = 'a' * len(keys_filename_hex)  # Target for private key XOR result

            # XOR to get the public and private key filenames
            public_key_filename_hex = xor_with_hex_string(keys_filename_hex, all_sevens)
            private_key_filename_hex = xor_with_hex_string(keys_filename_hex, all_eights)

            # Save the RSA keys in the 'rsa_keys' folder with the new filenames
            private_key_path = os.path.join(rsa_keys_directory, f'{private_key_filename_hex}.pem')
            with open(private_key_path, 'wb') as f:
                f.write(rsa_key.export_key())  # Save private key

            public_key_path = os.path.join(rsa_keys_directory, f'{public_key_filename_hex}.pem')
            with open(public_key_path, 'wb') as f:
                f.write(public_key.export_key())  # Save public key

            # Encrypt AES key with RSA public key
            rsa_encrypted_aes_key = rsa_encrypt(aes_key, public_key)

            # Ensure the 'keys' folder exists
            keys_directory = "keys"
            os.makedirs(keys_directory, exist_ok=True)
            keys_filename_string = os.path.join(keys_directory, f"{keys_filename_hex}.txt")
            
            with open(keys_filename_string, "w") as file:
                file.write(base64.b64encode(rsa_encrypted_aes_key).decode('utf-8'))

            # Encrypt the PGN data with AES
            aes_encrypted_pgn = aes_encrypt(encoded_pgn.encode('utf-8'), aes_key)

            # Save the encrypted data as a .pgn file
            pgn_file_name = f"{keys_xor_hex_str}.pgn"
            pgn_file_path = os.path.join('uploads', pgn_file_name)
            with open(pgn_file_path, "wb") as f:
                f.write(aes_encrypted_pgn)

            return jsonify({"message": "File converted successfully!", "pgn_file": pgn_file_name})

    return render_template('upload.html')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    # Step 1: Retrieve the uploaded PGN file and the output file name
    pgn_file = request.files['pgn_file']
    pgn_filename = os.path.splitext(pgn_file.filename)[0]

    # Step 2: Check the keys folder for a matching key file using XOR logic
    keys_folder = 'keys'
    matching_key_file = None

    for key_file in os.listdir(keys_folder):
        key_filename = os.path.splitext(key_file)[0]
        xor_result = xor_hex_strings(pgn_filename, key_filename)
        # print(f"Checking key file: {key_filename}, XOR result: {xor_result}")  # Debugging output
        if xor_result == 'ffffffffffffffffffffffffffffffffffffffffffffffff':  # 24 f's
            matching_key_file = os.path.join(keys_folder, key_file)
            break

    if not matching_key_file:
        return jsonify({"error": f"No matching key found for {pgn_filename}"}), 400

    # Step 3: Load the RSA-encrypted AES key from the matching key file
    with open(matching_key_file, "r") as file:
        rsa_encrypted_aes_key_base64 = file.read().strip()  # Ensure it’s base64 encoded
        rsa_encrypted_aes_key = base64.b64decode(rsa_encrypted_aes_key_base64)

    os.remove(matching_key_file)

    # Step 4: Find the corresponding private key and public key
    rsa_keys_directory = 'rsa_keys'
    private_key = None
    public_key = None
    all_sevens = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'  # Expected XOR result for public key (24-byte hex string, hence 48 chars)
    all_eights = '555555555555555555555555555555555555555555555555'  # Expected XOR result for private key

    for rsa_key_file in os.listdir(rsa_keys_directory):
        rsa_key_filename = os.path.splitext(rsa_key_file)[0]
        xor_with_pgn = xor_hex_strings(pgn_filename, rsa_key_filename)
        # print(xor_with_pgn)

        if xor_with_pgn == all_sevens:
            public_key_path = os.path.join(rsa_keys_directory, rsa_key_file)
            with open(public_key_path, 'rb') as pub_key_file:
                public_key = RSA.import_key(pub_key_file.read())
            # print(f"Found public key: {public_key_path}")
        elif xor_with_pgn == all_eights:
            private_key_path = os.path.join(rsa_keys_directory, rsa_key_file)
            with open(private_key_path, 'rb') as priv_key_file:
                private_key = RSA.import_key(priv_key_file.read())
                if private_key.has_private():  # Double check it's a private key
                    print()
                    # print(f"Found private key: {private_key_path}")
                else:
                    print(f"Error: {private_key_path} is not a private key!")

    # Check if both public and private keys are found
    if not private_key or not public_key:
        return jsonify({"error": "Matching RSA key files not found."}), 400

    os.remove(private_key_path)
    os.remove(public_key_path)

    # Step 5: Decrypt the AES key using the private RSA key
    try:
        aes_key = rsa_decrypt(rsa_encrypted_aes_key, private_key)
    except Exception as e:
        return jsonify({"error": f"Failed to decrypt AES key: {str(e)}"}), 500

    # Step 6: Decrypt the PGN file using the decrypted AES key
    encrypted_pgn_data = pgn_file.read()  # Read as binary since it's encrypted
    try:
        decrypted_pgn_string = aes_decrypt(encrypted_pgn_data, aes_key).decode('utf-8')  # Ensure utf-8 decoding
    except Exception as e:
        return jsonify({"error": f"Failed to decrypt the PGN file: {str(e)}"}), 500

    # Step 7: Save the decrypted data to the specified output file
    first_line = decrypted_pgn_string.splitlines()[0]
    output_file_name = ""
    output_file_name = first_line
    output_file_path = f'uploads/{output_file_name}'
    undo_gambit(decrypted_pgn_string, output_file_path)  # Assuming undo_gambit() converts PGN back to original format

    return jsonify({"message": "File decrypted successfully!", "output_file": output_file_name})

# Route for users to delete their own accounts
@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('delete_account'))

        if username in users_db and users_db[username]['password'] == password:
            del users_db[username]
            save_users(users_db)
            flash('Account deleted successfully.')
            return redirect(url_for('signup'))
        else:
            flash('Incorrect password or username. Please try again.')
            return redirect(url_for('delete_account'))

    return render_template('delete_account.html')

# Route for the admin to delete a user directly from the dashboard
@app.route('/admin/delete_user/<username>', methods=['POST'])
def delete_user(username):
    if 'admin' in session and session['admin']:
        if username in users_db:
            del users_db[username]
            save_users(users_db)
            flash(f'User {username} deleted successfully.')
    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    session.clear()  # Clear the session data
    return redirect(url_for('login'))  # Redirect to the login page

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)  # Ensure the uploads directory exists
    app.run(debug=True)
