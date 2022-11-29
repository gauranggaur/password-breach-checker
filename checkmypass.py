import requests      # for sending API requests
import hashlib       # built-in python module for hashing the password before sending it to the API
import sys           # to grab passwords passed in the terminal 

# Here we request data from the API by submitting our first 5 char of hashed password
def request_api_data(hashed_char):
    url = f'https://api.pwnedpasswords.com/range/{hashed_char}'
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"Error fetching: {response.status_code}, Chck the API and try again.")
    return response.text

# Here we check if our password (like, john@123) exists in the received data list 
def pwned_api_check(password):
    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()   # hashed our password
    pass_head = hashed_password[:5]                                        # got the first 5 char
    pass_tail = hashed_password[5:]                                        # got the rest of char (tail)
    response = request_api_data(pass_head)                                 # passed in the API
    return get_password_leaks_count(response, pass_tail)                   # finding our own password from the list data we received and getting the count


# As now we have fetched the data from the API, here we will get the password leaks count of our SPECIFIC hashed password by matching with tail
def get_password_leaks_count(hashes, hash_to_check):
    splitted_hashes = (item.split(":") for item in hashes.splitlines())   # separating hash value and count and storing inside touple via comprehension
    for hash, count in splitted_hashes:
        if hash == hash_to_check:
            return count 
    return 0
    

# We pass terminal password arg in main(), it calls pwned_api_check(), which hashes the pass and call request_api_data() 
# and pass the response to get_password_leaks_count() which returns a count. We receive the count and respond accordingly to user
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times. You should probably change your password")
        else:
            print(f"{password} was found 0 times. It is safe to use.")
    return 'done!'

if __name__ == "__main__" :  # Only run the function if it is running as main file and not imported
    # sys.exit helps us exit the entire process
    sys.exit(main(sys.argv[1:]))   # passing all terminal arguments (passwords) except the file name which is item [0]
