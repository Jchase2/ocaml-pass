(* Copyright (C) 2015 JChase2
This code is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public
License as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details. *)

open Nocrypto.Cipher_block
open Printf
   
(* ============================== GLOBAL EXPRESSIONS ========================== *)
let cryptfile = "ocamlpass.crypt"
let filebuff = Buffer.create 500 (* This is the read in file on program launch. *)
let globalbuff = Buffer.create 500 (* Utility buffer for user input / re-encryption stuff. *)
let keystore = ref ""
let tmpkstore = ref ""

(* Help Dialogue *)
let help = [
    " ";
    "Type 'read' to read the entire file.";
    "Type 'bsearch' to search for and print a block.";
    "Type 'block' to insert a new password block.";
    "Type 'rb' to remove a block.";
    "Type 'q' to quit."
]

(* =============================== Crypt Utilities ============================================= *)

(* dectohex and hex2dec are just associative lists to get values for
hex, which are used for padding, except G which is added so it's still a single char.
Am considering replacing these with a map, although they're small so performance is fine. *)
    
let dectohex (x) =
  let hexlist =
    [1, '1'; 2, '2'; 3, '3'; 4, '4'; 5, '5';
     6, '6'; 7, '7'; 8, '8'; 9, '9'; 10, 'A';
     11, 'B'; 12, 'C'; 13, 'D'; 14, 'E'; 15, 'F'; 16, 'G'] in 
  let ret = List.assoc x hexlist in
(ret)

let hextodec (x) =
  let hexlist =
    ['1', 1; '2', 2; '3', 3; '4', 4; '5', 5; '6', 6;
     '7', 7; '8', 8; '9', 9; 'A', 10; 'B', 11; 'C', 12;
     'D', 13; 'E', 14; 'F', 15; 'G', 16] in
  let ret = List.assoc x hexlist in
(ret)
    
(* Copies bytes to buffer, except the first 16 bytes. *)
(* This essentially helps remove the IV prior to decryption. *)
let removeiv bytestream buff () =
  for i = 16 to ((Bytes.length bytestream - 1)) do
    Buffer.add_char buff (Bytes.get bytestream i)
  done ;
()

(* Reverses a string... *)
let rev_string str =
  let len = String.length str in
  let res = (Bytes.to_string (Bytes.create len)) in
  let last = len - 1 in
  for i = 0 to last do
    let j = last - i in
    res.[i] <- str.[j];
  done;
(res)


(* Recursive function to get padding length. *)
let padlen byts () =
  let i = ref 0 in
  let rec loop () =
    let bytelength = (Bytes.length byts) in
    if ((bytelength mod 16) = 0) then
      begin
        i := 16;
        ()
      end
    else if ((bytelength + !i) mod 16) != 0 then
      begin
        i := (!i + 1);
        loop ()
      end ;
  in
  loop();
(!i)

(* Read cryptfile into a bytestream. *)
let readtobytes () =
  let ic = open_in_gen [Open_creat] 0o664 cryptfile in
  let n = in_channel_length ic in
  let s = Bytes.create n in
  really_input ic s 0 n;
  close_in ic;
(s)

         
(* =============================== Encryption / Decryption ========================== *)

(* This takes a given message and encrypts it. Key is temporary. *)
(* Used for storing the actual key and for encpyting and decrypting buffers. *)
let quickcrypt (message) =
  let () = Nocrypto_entropy_unix.initialize () in
  let randnum = Nocrypto.Rng.generate 256 in (* Random numbers *)
  let randhash = Nocrypto.Hash.SHA256.digest randnum in (* Hash of randnum *)
  let cshashbytes = Bytes.of_string (Cstruct.to_string randhash) in
  let cutbytes = Bytes.sub cshashbytes 0 16 in (* cut the bytes from above down to 16 bytes. *)
  let iv = (Cstruct.of_string (Bytes.to_string cutbytes)) in (*Get IV, string of cutbytes. *)
  let paddingsize = padlen message () in
  let paddingbyte = dectohex paddingsize in
  let padding = Bytes.make paddingsize paddingbyte in
  let key =  AES.CBC.of_secret (Cstruct.of_string !tmpkstore) in
  let cipher_padding = message ^ padding in
  let ciphertext = AES.CBC.encrypt ~key ~iv (Cstruct.of_string (cipher_padding)) in
  let cipher_iv = (Cstruct.to_string iv) ^ (Cstruct.to_string ciphertext) in
  Gc.full_major ();
(cipher_iv)

(* Decrypts whatever quickcrypt encrypted using it's key. *) 
let quickdecrypt (cipher) =
  let s = cipher in
  let a = String.sub cipher 16 ((String.length cipher) - 16) in
  let iv = (Cstruct.of_string (Bytes.sub_string s 0 16)) in
  let key =  AES.CBC.of_secret (Cstruct.of_string !tmpkstore) in
  let txtpadding = AES.CBC.decrypt ~key ~iv (Cstruct.of_string a) in
  let lastbyte =  ((Cstruct.to_string txtpadding).[String.length (Cstruct.to_string txtpadding) - 1]) in
  let toremove = hextodec lastbyte in
  let reversed_txt =
    (Bytes.sub_string (rev_string (Cstruct.to_string txtpadding)) toremove
                      ((String.length (Cstruct.to_string txtpadding)) - toremove)) in
  let txt = rev_string reversed_txt in
(txt)

let cryptbuff buff () =
      let localbuff = Buffer.create 500 in
      Buffer.add_string localbuff (quickcrypt (Buffer.contents buff));
      Buffer.clear buff;
      Buffer.add_buffer buff localbuff;
      Buffer.clear localbuff;
()

let decryptbuff buff () =
  if (Buffer.length buff = 0) then
    ()
  else begin
      let localbuff = Buffer.create 500 in
      Buffer.add_string localbuff (quickdecrypt (Buffer.contents buff));
      Buffer.clear buff;
      Buffer.add_buffer buff localbuff;
      Buffer.clear localbuff;
    end;    
()
  
(* Load in encrypted file *)
(* Also decrypt it. *)
(* Could probably use some more factoring... *)
let load_file () =
  let s = readtobytes () in
  if ((Bytes.length s) > 0) then
    let localbuff = Buffer.create 500 in
    removeiv s localbuff ();
    (* Set up decryption parameters *)
    let iv = (Cstruct.of_string (Bytes.sub_string s 0 16)) in
    let mykey = (Cstruct.of_string (quickdecrypt !keystore)) in
    let key = AES.CBC.of_secret mykey in (* Generate usable key from mykey *)
    (* txtpadding is decrypted file with padding still included...*)
    let txtpadding = AES.CBC.decrypt ~key ~iv (Cstruct.of_string (Buffer.contents localbuff)) in
    let lastbyte =  ((Cstruct.to_string txtpadding).[String.length (Cstruct.to_string txtpadding) - 1]) in 
    let toremove = hextodec lastbyte in
    let reversed_txt =
      (Bytes.sub_string (rev_string (Cstruct.to_string txtpadding)) toremove
                        ((String.length (Cstruct.to_string txtpadding)) - toremove)) in
    let plaintext = rev_string reversed_txt in
    Buffer.clear localbuff ;
    Buffer.add_string filebuff plaintext ;
    cryptbuff filebuff ();
  else begin
      print_endline "File does not exist! A new file has been created." ;
      print_endline "Type '?' or 'help' for usage." ;
    end ;
()

(* Encrypt contents of buffer, write to file. *)
(* Prepend IV, append padding. *)
(* Replaces contents of cryptfile with contents of buf! 
   never call without first merging buffers! *)
let encrypt buf () =
  let () = Nocrypto_entropy_unix.initialize () in (* Seeding from /dev/urandom *)
  let cs = Nocrypto.Rng.generate 256 in (* Random numbers *)
  let cshash = Nocrypto.Hash.SHA256.digest cs in (* Hash of cs *)
  let cshashbytes = Bytes.of_string (Cstruct.to_string cshash) in
  let cutbytes = Bytes.sub cshashbytes 0 16 in (* cut the bytes from above down to 16 bytes. *)
  let iv = (Cstruct.of_string (Bytes.to_string cutbytes)) in (*Get IV, string of cutbytes. *)
  let mykey = (Cstruct.of_string (quickdecrypt !keystore)) in
  let key = AES.CBC.of_secret mykey in (* Generate usable key from mykey *)
  let bytecontent = (Buffer.to_bytes buf) in
  let paddingsize = padlen bytecontent () in
  let paddingbyte = dectohex paddingsize in    
  let padding = Bytes.make paddingsize paddingbyte in
  Buffer.add_bytes buf padding;
  let ciphertext = AES.CBC.encrypt ~key ~iv (Cstruct.of_string (Buffer.contents buf)) in
  let oc = open_out cryptfile in
  output_string oc (Cstruct.to_string iv);
  output_string oc (Cstruct.to_string ciphertext);
  flush oc;
  close_out oc;
()
 
             
(* ============================== UTILITIES =========================== *)

(* PRINT LIST STRING *)
let rec print_list_string mylist () = match mylist with
  | [] -> print_endline " "
  | head::body ->
     begin
       print_endline head;
       print_list_string body
     end
()

(* Merges the buffers... *)
(* Should only be used if new block was added. *)
let mergecrypt () =
  decryptbuff globalbuff ();
  decryptbuff filebuff ();
  Buffer.add_char filebuff '\n';
  Buffer.add_buffer filebuff globalbuff ; (* Adds globalbuff to end of initial. *)
  Buffer.clear globalbuff ;
  cryptbuff filebuff ();
  cryptbuff globalbuff ();
()

let read () =
  decryptbuff filebuff ();
  print_endline (Buffer.contents filebuff) ;
  cryptbuff filebuff ();
()

    
(* ======================== Insertion / Searching Functions ========================= *)

(* Insert Block *)

let rec createblock () =
  (* Creates block, reads in from user *)
  let localbuff = Buffer.create 100 in
  let a = "==== " in
  let b = " ====" in
  let d = "==== END ====" in
  print_endline "";
  print_string "Type block name: ";
  let astr = read_line () in
  let c = a ^ astr ^ b in
  Buffer.add_string localbuff c ;
  Buffer.add_char localbuff '\n';
  let quit_loop = ref false in 
  while (not !quit_loop) do 
    print_endline "Type 'done' when finished entering. " ;
    print_string "Enter String: ";
    let astr = read_line () in 
    if astr <> "done" then
      begin
        Buffer.add_string localbuff astr;
        Buffer.add_char localbuff '\n';
      end
    else
      begin
        quit_loop := true
      end 
  done;         
  Buffer.add_string localbuff d;
  print_endline (Buffer.contents localbuff);
  print_endline "Does this look correct? (y/n): ";
  let astr = read_line () in
  if (astr = "y") then
    begin
      decryptbuff globalbuff ();
      Buffer.add_buffer globalbuff localbuff;
      Buffer.clear localbuff;
      cryptbuff globalbuff ();
      mergecrypt() ;
    end
  else if (astr = "yes") then
    begin
      decryptbuff globalbuff ();
      Buffer.add_buffer globalbuff localbuff;
      Buffer.clear localbuff;
      cryptbuff globalbuff ();
      mergecrypt() ;
    end
  else if (astr = "n") then
    begin
      Buffer.clear localbuff;
      createblock () ;
    end
  else if (astr = "no") then
    begin
      Buffer.clear localbuff;
      createblock () ;
    end
  else
    begin
      print_endline "Invalid Input" ;
      print_endline "Assuming yes for now. " ;
      decryptbuff globalbuff ();
      Buffer.add_buffer globalbuff localbuff;
      Buffer.clear localbuff;
      mergecrypt() ;
      cryptbuff globalbuff ();
    end ;
()

(* Search for and output block. *)
let search_block () =
  decryptbuff filebuff ();
  print_string "Enter block name: " ;
  let block_name = read_line () in
  let block_title = "==== "^block_name^" ====" in
  let block_end = "==== END ====" in
  let regex = Pcre.regexp ~flags:[`DOTALL; `CASELESS; `MULTILINE]  (block_title^".*?"^block_end) in
  let x = Pcre.extract ~rex:regex (Buffer.contents filebuff) in
  print_endline (Array.get x 0);
  cryptbuff filebuff ();
()

let remove_block () =
  decryptbuff filebuff ();
  print_string "Enter block name to remove: " ;
  let block_name = read_line () in
  let block_title = "==== "^block_name^" ====" in
  let block_end = "==== END ====" in
  let regex = Pcre.regexp ~flags:[`DOTALL; `CASELESS; `MULTILINE]  (block_title^".*?"^block_end) in
  let x = Pcre.replace ~rex:regex (Buffer.contents filebuff) in
  print_endline x;
  Buffer.clear filebuff;
  Buffer.add_string filebuff x;
  cryptbuff filebuff ();
()

(* =============================== MAIN and Configure ============================ *)

(* Main interaction loop via tail recursion. *)
(* Mostly just a large if statement... *)
(* More functional alternative? *)

let rec main_loop () =
  print_endline "";
  print_endline "Type '?' or 'help' to print dialogue box. ";
  print_string "Command: ";
  let str = read_line () in
  if str = "exit" then begin
      decryptbuff filebuff ();
      encrypt filebuff ();
      Gc.full_major ();
      exit 0;
      ()
    end
  else if str = "quit" then
    begin
      decryptbuff filebuff ();
      encrypt filebuff ();
      Gc.full_major ();
      exit 0;
      ()
    end
  else if str = "q" then
    begin
      decryptbuff filebuff ();
      encrypt filebuff ();
      Gc.full_major ();
      exit 0;
      ()
    end
  else if str = "help" then begin
      print_list_string help ();
      main_loop ()
    end
  else if str = "?" then begin
      print_list_string help ();
      main_loop ()
    end
  else if str = "block" then begin
      createblock();
      main_loop()
    end
  else if str = "read" then begin
      read();
      main_loop()
    end
  else if str = "bsearch" then begin
      search_block();
      main_loop()
    end
  else if str = "crypt" then begin
      print_endline (quickcrypt str);
      main_loop()
    end
  else if str = "rb" then begin
      remove_block ();
      main_loop ()
    end
  else begin
      print_endline "";
      print_endline "That is not a defined option. ";
      main_loop ()
    end;
()
  
(* Configure pw, generate scrypt key, decrypt and load in file on launch. *)
let login () =
  let salt = (Cstruct.of_string "rN)K_=BPCeQj83SbA)zi-Zgd8S88`ZFWI;+uK/1}H#w&?ATgo9|=zT(y+2DjlO|O") in
  let n = 16384 (* CPU / memory cost Parameter *) in
  let r = 8 (* Specifies the block size in bytes for scrypt *) in
  let p = 4 (* Paralellization parameter for scrypt. *) in
  let dk_len = 32l (* Length of key, 8 * blocksize = 256. Is AES Max key size. *) in
  print_endline "";
  print_string "Password: ";
  let password = (Cstruct.of_string (read_line())) in
  let () = Nocrypto_entropy_unix.initialize () in
  tmpkstore := (Cstruct.to_string (Nocrypto.Rng.generate 16));
  let mykey = Scrypt_kdf.scrypt_kdf ~password ~salt ~n ~r ~p ~dk_len in
  keystore := quickcrypt (Cstruct.to_string mykey);
  let password = "" in (* Might overwrite if not on heap, if I'm understanding correctly. *)
  load_file ();
  print_endline "Logged in. ";
  Gc.full_major (); (* Garbage collect, most of this should get collected. *)
  main_loop() ;
;; (* Can I get rid of the ';;' here? *)

login();
main_loop()
