from encrypt import Encrypt,Dencrypt,File_object
import PySimpleGUI as sg
from secrets import token_bytes
import bcrypt, base64, copy
from passwd_manager import Passwd_manager,key_padding,check_key
my_passwd = Passwd_manager('passwd.json','passwd.key')
my_passwd.read_json()
my_passwd.read_en_passwd()
sg.theme('SystemDefaultForReal')
menu_def = [
    ['Manage Password',['Password Manager']],
]
table_headings = ['File','Password']
layout = [
            [sg.Menu(menu_def)],
            [sg.Text('aes encrypt')],
            [sg.Text('Please select the file'), sg.FileBrowse('File',target='-selectFile-'), sg.Input(key='-selectFile-')],
            [sg.Text('Please select the mode')],
            [sg.Radio('Encrypt', "RADIO1",default=True), sg.Radio('Dencrypt', "RADIO1",key='-dencrypt-')],
            [sg.Checkbox('Save key',size=(10,1), default=True)],
            [sg.Multiline(key = '-passwdInput-' ,size=(40,2)),sg.Button('Generate key'),sg.Combo(['128-bit', '256-bit'],default_value='256-bit')],
            [sg.Button('Find key', key='-findKey-',size=(6,1)),sg.Text('',key='-info-')],
            [sg.Button('OK'), sg.Button('Cancel')] 
            ]
         

def dispaly_manager(manager,manager_layout):
    manager_window = sg.Window('Password Manager',manager_layout,size=(500,400))
    while True:
        event,values = manager_window.read()
        if event in (None, 'Cancel'):
            manager_window.close()
            return None
        if values['-keyList-'] == []:
            sg.popup_ok('No file selected')
        elif event == '-selectFile-':
            manager_window.close()
            return values['-keyList-'][0]
        elif event == 'Delete':
            t = sg.popup_ok_cancel('Are you sure to delete the key?')
            if t == 'OK':
                manager.remove_key(my_passwd.den_list[values['-keyList-'][0]][0])
                manager.write_json()
                manager_window.find_element('-keyList-').update(my_passwd.den_list)
def dencrypt_list(key_list,passwd):
    l = copy.deepcopy(key_list)
    for i in range(0,len(l)):
        en_key = bytes.fromhex(l[i][1])
        den_key = Dencrypt(en_key,key_padding(passwd.encode()))
        den_key.ECB()
        den_key = den_key.den_text
        l[i][1] = den_key.decode()
    return l
window = sg.Window('Easyfcrypt', layout,size=(510,400),grab_anywhere=True )
while True:
    event, values = window.read()
    if event in (None, 'Cancel'):
        break
    file = values['-selectFile-']
    if event == 'Password Manager':
        if my_passwd.en_passwd == b'':
            manage_key = sg.popup_get_text('Please set your password','Password Manager') 
            if check_key(manage_key) == True:
                my_passwd.verified = True
                my_passwd.en_passwd = bcrypt.hashpw(manage_key.encode(), bcrypt.gensalt(rounds=16))
                my_passwd.den_passwd = manage_key
                my_passwd.write_en_passwd()
            elif check_key(manage_key) == False:
                sg.popup_ok('The password should be eight to 16 bits and contain no spaces')
        else:
            if my_passwd.verified == False:
                manage_key = sg.popup_get_text('Please enter your password','Password Manager')
                if manage_key != None:
                    if bcrypt.checkpw(manage_key.encode(),my_passwd.en_passwd):
                        my_passwd.verified = True
                        my_passwd.den_passwd = manage_key
                    else:
                        sg.popup_ok('Wrong password')
        if my_passwd.verified == True:
            if my_passwd.is_dencrypted == False:        
                if my_passwd.en_list != []:
                    my_passwd.den_list = dencrypt_list(my_passwd.en_list,my_passwd.den_passwd)
                my_passwd.is_dencrypted =True
            pwd_manager_layout = [
        [sg.Table(my_passwd.den_list,headings=table_headings,auto_size_columns = True,select_mode = 'browse', key='-keyList-')],
        [sg.Button('OK',key='-selectFile-'), sg.Button('Delete'), sg.Button('Cancel')]
    ]
            window.hide()
            selected_file = dispaly_manager(my_passwd,pwd_manager_layout)
            if selected_file != None:
                window.find_element('-info-').update('Find key')
                window.find_element('-dencrypt-').update(value = True)
                window.find_element('-selectFile-').update(my_passwd.den_list[selected_file][0])
                window.find_element('-passwdInput-').update(my_passwd.den_list[selected_file][1])
            window.un_hide()
    elif event == '-findKey-':
         if my_passwd.verified ==True:
                den_key = my_passwd.find_file_passwd(file)
                if den_key != None:
                    window.find_element('-info-').update('Find key')
                    window.find_element('-dencrypt-').update(value = True)
                    window.find_element('-passwdInput-').update(den_key)
                else:
                    window.find_element('-info-').update('No key found')
    elif event == 'Generate key':
        if values[3] == '128-bit':
            window.find_element('-passwdInput-').update(base64.b85encode(token_bytes(nbytes=6)).decode()
             + base64.b85encode(token_bytes(nbytes=6)).decode()
)
        elif values[3] == '256-bit':
            window.find_element('-passwdInput-').update(base64.b85encode(token_bytes(nbytes=25)).decode())
    elif file == '':
        sg.popup_ok('Please select the file')
    

    elif values[1] == True or values['-dencrypt-'] == True:
        key = values['-passwdInput-'].encode()
        key = key_padding(key)
        f = File_object(file)
        f_bytes = f.read_bytes()
        if f_bytes == None:
            sg.popup_error('File does not exist')
        elif len(key)>32:
            sg.popup_error('Keys are too long')
        elif key == b'':
            sg.popup_error('The key should not be empty')
        elif values[1] ==True:
            a = Encrypt(f.read_bytes(), key)
            a.pkcs7()
            en_text = a.ECB()
            try:
                f.write_bytes(en_text)
            except PermissionError:
                sg.popup_error('Not enough permissions')
            else:
                if values[2] == True and my_passwd.verified == True:
                    en_passwd = Encrypt(key, key_padding(my_passwd.den_passwd.encode()))
                    en_passwd = en_passwd.ECB()
                    my_passwd.update_json([file, en_passwd.hex()])
                    my_passwd.den_list.insert(0,[file, key.decode()])
                    my_passwd.write_json()
                sg.popup_ok(file + ' Encrypt successfully')
        elif values['-dencrypt-'] ==True:
            b = Dencrypt(f.read_bytes(), key)
            try:
                b.ECB()
            except ValueError:
                sg.popup_error('The number of file bytes is not a multiple of 16',title='Wrong file')
            else:
                den_text = b.pkcs7()
                if den_text == None:
                    sg.popup_ok('Wrong key')
                else:
                    try:
                        f.write_bytes(den_text)
                    except PermissionError:
                        sg.popup_error('Not enough permissions')
                    else:
                        my_passwd.remove_key(file)
                        my_passwd.write_json()
                        sg.popup_ok(file + ' Dencrypt successfully')


window.close()