"""
Routes and views for the flask application.

"""


#my python functions



import argparse
import math
import pefile
import logging
import argparse
import math
import pefile
import hashlib
import os
import subprocess
import json
import pandas as pd
import numpy as np
import requests
import json
import hashlib
from pathlib import Path
import time
from datetime import datetime
import exiftool
from os.path import exists
import time
import sys
from datetime import date
import warnings
warnings.filterwarnings('ignore')

unknwn_exe_dir = r"./dir_upload/"
unknwn_json_output_dir = r"./dir_upload/unknown_Exiftool_Json/"
unknwn_output_dir = r"./dir_upload/unknown_output_dir/"


############################################################################################################

today = date.today()
todayDate = today.strftime("%d_%m_%Y")
file_name = "unknown_metadata_none_full_" + todayDate
file_type = ".pkl"

print("This file will be create:", file_name + file_type)



def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


############################################################################################################


def shannon_entropy(data):
    # 256 different possible values
    possible = dict(((chr(x), 0) for x in range(0, 256)))

    for byte in data:
        possible[chr(byte)] +=1

    data_len = len(data)
    entropy = 0.0
    
    # compute
    for i in possible:
        if possible[i] == 0:
            continue

        p = float(possible[i] / data_len)
        entropy -= p * math.log(p, 2)
    app.logger.info("shannon_entropy() funstion is finished")
    return entropy


############################################################################################################


def is_exe(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)


############################################################################################################

def import_table_list(indx, path, df):
        #if not is_exe(path):
        #pe = pefile.PE(path)
    #else:
        #return df
    ispe = "Yes"
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError:
        app.logger.error("Not a PE")
        ispe = "No"
    if ispe != "No":
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                #print(entry.dll.decode('UTF-8'))
                lib_name = entry.dll.decode('UTF-8').lower()
                for imp in entry.imports:
                    func_name = imp.name.decode('UTF-8').lower()
                    #_txt = imp.name
                    #_txt.replace("b", "")
                    #_txt2 = _txt[0:-1]
                    #print(lib_name + '_' + func_name)
                    df.at[indx, lib_name + '_' + func_name] = int(1)
        except:
            df.at[indx, "import_table_list_succeeded"] = False
            return df
    #print(df)
    df.at[indx, "import_table_list_succeeded"] = True
    app.logger.info("import_table_list() function is finished")
    return df


############################################################################################################


def sections_entropy(indx, path, df):
    va = "_virtualaddress"
    vs = "_virtualsize"
    rs = "_rawsize"
    ey ="_entropy"

    ispe = "Yes"
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError:
        app.logger.error("Not a PE:")
        app.logger.error(path)
        ispe = "No"
    if ispe != "No":
        try:
            for section in pe.sections:
                section_name = section.Name.decode('utf-8')[1:].lower()
                df.at[indx, section_name + va] = int(hex(section.VirtualAddress), 16)
                df.at[indx, section_name + vs] = int(hex(section.Misc_VirtualSize), 16)
                df.at[indx, section_name + rs] = int(hex(section.SizeOfRawData), 16)
                df.at[indx, section_name + ey] = float(shannon_entropy(section.get_data()))
                #print("\tvirtual address: " + hex(section.VirtualAddress))        
                #print("\tvirtual size: " + hex(section.Misc_VirtualSize))
                #print("\traw size: " + hex(section.SizeOfRawData))
                #print ("\tentropy: " + str(shannon_entropy(section.get_data())))
                #print(df)
        except:
            df.at[indx, "sections_entropy_succeeded"] = False
            return df
    df.at[indx, "sections_entropy_succeeded"] = True
    app.logger.info("sections_entropy() function is finished")
    return df


############################################################################################################


def run_exiftool(full_file_path, json_output_dir, file_sha256, df, indx):
    full_json_output_path = json_output_dir + file_sha256 + ".json"
    if Path(full_json_output_path).is_file():
        app.logger.info("Already exported: -" + file_sha256 + '-')
    else:
        #print(full_json_output_path)
        with open(full_json_output_path, "w+") as json_file:
            exiftool_command = ["exiftool", "-json", full_file_path]
            subprocess.run(exiftool_command, stdout=json_file)
        app.logger.info("JSON File Exported: -" + file_sha256 + '-')
    
    try:
        json_file = open(full_json_output_path)
        json_data = json.load(json_file)[0]
    except:
        app.logger.error("An exception occurred for file hash:", file_sha256)
        app.logger.error(full_json_output_path)
        df.at[indx, 'exiftool_succeeded'] = False
        return 
    #if "FileName" in json_data:
        #df.at[indx, 'filename'] = json_data['FileName']
    #if "Directory" in json_data:
        #df.at[indx, 'directory'] = json_data['Directory']
    if "FileSize" in json_data:
        realFileSize = 0
        fileN = float(json_data['FileSize'].split(" ", 1)[0])
        fileE = json_data['FileSize'].split(" ", 1)[1]
        if fileE == 'KiB':
            realFileSize = fileN * 1024
        if fileE == 'MiB':
            realFileSize = fileN * 1024 * 1024
        if fileE == 'GiB':
            realFileSize = fileN * 1024 * 1024 * 1024
        df.at[indx, 'file_size'] = realFileSize
    if "FileModifyDate" in json_data:
        df.at[indx, 'filemodify_date'] = json_data['FileModifyDate'].split(" ", 1)[0]
    if "FileAccessDate" in json_data:
        df.at[indx, 'file_access_date'] = json_data['FileAccessDate'].split(" ", 1)[0]
    if "FileInodeChangeDate" in json_data:
        df.at[indx, 'file_inode_change_date'] = json_data['FileInodeChangeDate'].split(" ", 1)[0]
    if "FilePermissions" in json_data:
        df.at[indx, 'file_permissions'] = json_data['FilePermissions']
    if "FileType" in json_data:
        df.at[indx, 'filetype'] = json_data['FileType']
    if "FileTypeExtension" in json_data:
        df.at[indx, 'file_type_extension'] = json_data['FileTypeExtension']
    if "MIMEType" in json_data:
        df.at[indx, 'mimetype'] = json_data['MIMEType']
    if "MachineType" in json_data:
        df.at[indx, 'machine_type'] = json_data['MachineType']
    if "TimeStamp" in json_data:
        df.at[indx, 'timestamp'] = json_data['TimeStamp'].split(" ", 1)[0]
    if "ImageFileCharacteristics" in json_data:
        df.at[indx, 'image_file_characteristics'] = json_data['ImageFileCharacteristics']
    if "PEType" in json_data:
        df.at[indx, 'petype'] = json_data['PEType'] 
    if "LinkerVersion" in json_data:
        df.at[indx, 'linker_version'] = json_data['LinkerVersion']
    if "CodeSize" in json_data:
        df.at[indx, 'code_size'] = json_data['CodeSize']
    if "InitializedDataSize" in json_data:
        df.at[indx, 'initialized_data_size'] = json_data['InitializedDataSize']
    if "UninitializedDataSize" in json_data:
        df.at[indx, 'uninitialized_data_size'] = json_data['UninitializedDataSize']
    if "EntryPoint" in json_data:
        df.at[indx, 'entrypoint'] = int(json_data['EntryPoint'], 16)
    if "OSVersion" in json_data:
        df.at[indx, 'directory'] = json_data['OSVersion']
    if "ImageVersion" in json_data:
        df.at[indx, 'os_version'] = json_data['ImageVersion']
    if "SubsystemVersion" in json_data:
        df.at[indx, 'subsystem_version'] = json_data['SubsystemVersion']
    if "Subsystem" in json_data:
        df.at[indx, 'subsystem'] = json_data['Subsystem']
    if "FileVersionNumber" in json_data:
        df.at[indx, 'file_version_number'] = json_data['FileVersionNumber']
    if "ProductVersionNumber" in json_data:
        df.at[indx, 'product_version_number'] = json_data['ProductVersionNumber'] 
    if "FileFlagsMask" in json_data:
        df.at[indx, 'file_flags_mask'] = int(json_data['FileFlagsMask'], 16)
    if "FileFlags" in json_data:
        df.at[indx, 'file_flags'] = json_data['FileFlags']
    if "FileOS" in json_data:
        df.at[indx, 'file_os'] = json_data['FileOS']
    if "ObjectFileType" in json_data:
        df.at[indx, 'object_file_type'] = json_data['ObjectFileType']
    if "FileSubtype" in json_data:
        df.at[indx, 'file_subtype'] = json_data['FileSubtype']
    if "LanguageCode" in json_data:
        df.at[indx, 'language_code'] = json_data['LanguageCode']
    if "CharacterSet" in json_data:
        df.at[indx, 'character_set'] = json_data['CharacterSet']
    if "FileDescription" in json_data:
        df.at[indx, 'file_description'] = json_data['FileDescription']
    if "FileVersion" in json_data:
        df.at[indx, 'file_version'] = json_data['FileVersion']
    if "InternalName" in json_data:
        df.at[indx, 'internal_name'] = json_data['InternalName']
    if "LegalCopyright" in json_data:
        df.at[indx, 'legal_copyright'] = json_data['LegalCopyright']
    if "OriginalFileName" in json_data:
        df.at[indx, 'original_file_name'] = json_data['OriginalFileName']
    if "ProductName" in json_data:
        df.at[indx, 'product_name'] = json_data['ProductName']
    if "ProductVersion" in json_data:
        df.at[indx, 'product_version'] = json_data['ProductVersion']
    if "SquirrelAwareVersion" in json_data:
        df.at[indx, 'squirrel_aware_version'] = json_data['SquirrelAwareVersion']
    if "CompanyName" in json_data:
        df.at[indx, 'company_name'] = json_data['CompanyName']  
        #_filename = os.path.splitext(_file)[0]
        #print(_filename)
    json_file.close()
    app.logger.info("run_exiftool() function is finished")
    return df


############################################################################################################


def metadata_runner(filename, df):
    indx = 0
    extensions = ("exe", "Exe", "EXE", "msi", "Dll", "DLL", "dll")
    if not filename.endswith(extensions):
        app.logger.error("File Extension Error!")
        return df
    else:
        df_import = pd.DataFrame()
        df_section = pd.DataFrame()
        full_file_path = os.path.join(unknwn_exe_dir, filename)
        #print(os.path.join(r, file))
        sha256_hash = hashlib.sha256()
        with open(full_file_path,"rb") as f:
        # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
        df.at[indx, 'sha256_hash'] = sha256_hash.hexdigest()
        df = sections_entropy(indx, full_file_path, df)
        df = import_table_list(indx, full_file_path, df)
        df = run_exiftool(full_file_path, unknwn_json_output_dir, sha256_hash.hexdigest(), df, indx)
    app.logger.info("metadata_runner() function is finished")
    return df

def feature_engineering(df):
    #df = df.loc[:,~df.T.duplicated(keep='first')]
    df = df.drop_duplicates(subset=["sha256_hash"], keep='first')
    df = df.replace(np.nan, 0)
    df['filemodify_date'] = pd.to_datetime(df['filemodify_date'], errors = 'ignore')
    df['file_access_date'] = pd.to_datetime(df['file_access_date'], errors = 'ignore')
    df['file_inode_change_date'] = pd.to_datetime(df['file_inode_change_date'], errors = 'ignore')
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors = 'ignore')
    app.logger.info("feature_engineering() function is finished")
    return df

##########################################################################################################


import re

def parse_string_with_underscore_to_list(string):
    """Parses a string with underscore into a list without key-value.

    Args:
        string (str): The string to parse.

    Returns:
        list: A list containing the values in the string.
    """

    pattern = r'(\w+)(?:_(\w+))?'
    matches = re.findall(pattern, string)

    parsed_string = []
    for match in matches:
        value = match[1] if len(match) == 2 else match[0]
        parsed_string.append(value)


    return parsed_string


def get_file_type(filename):
    """Gets the file type in filename.

    Args:
        filename (str): The filename.

    Returns:
        str: The file type.
    """

    extension = os.path.splitext(filename)[1]
    file_type = extension[1:].lower()
    return file_type

##########################################################################################################



from datetime import datetime
from turtle import title
from ACSS import app

from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage

import os

from flask import render_template
from flask import Flask, flash, request, redirect, url_for


import logging

############################################################################################################

#From Jupyter



ALLOWED_EXTENSIONS = {'exe', 'msi', 'dll'}


############################################################################################################

@app.route('/')
@app.route('/home')
def home():
    """Renders the home page."""
    return render_template(
        'index.html',
        title='Home Page',
        year=datetime.now().year,
    )

@app.route('/contact')
def contact():
    """Renders the contact page."""
    return render_template(
        'contact.html',
        title='Contact',
        year=datetime.now().year,
        message='Imec-COSIC.'
    )

@app.route('/about')
def about():
    """Renders the about page."""
    return render_template(
        'about.html',
        title='About COSIC',
        year=datetime.now().year,
        message='COSIC'
    )

@app.route('/upload')
def upload():
    """Renders the upload page."""
    return render_template(
        'upload.html',
        title='Malware Analyser',
        year=datetime.now().year,
        message='by COSIC'
    )

@app.route('/extractor')
def extractor():
    """Renders the upload page."""
    return render_template(
        'extractor.html',
        title='PE Extractor',
        year=datetime.now().year,
        message='by COSIC'
    )

############################################################################################################


#control allowed file type 
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

############################################################################################################



@app.route('/analyse', methods=['GET', 'POST'])
def analyse():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'umodel' not in request.files:
            flash('No file part')
            return redirect(request.url)
        if 'usample' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        umodel = request.files['umodel']
        usample = request.files['usample']
        if umodel.filename == '':
            flash('No model selected')
            return redirect(request.url)
        if usample.filename == '':
            flash('No sample selected')
            return redirect(request.url)
        
        if get_file_type(umodel.filename) == 'sav':        
            modeltype = umodel.filename
        else:
            flash('No correct model selected')
        
        if allowed_file(usample.filename):
            samplename = usample.filename
        else:
            flash('No correct sample selected') 
               
        #app.logger.info("Before try-catch")
        
        try:
            automl = pickle.load(open("./engine/" + modeltype, 'rb'))
            app.logger.info('...:::Model is Loaded:::...')
          
            automl_model_statistics = pd.read_pickle(open("./engine/implicitPreProcessing_automl_wMetadata_wSections_experimental_results_automl_model_statistics_p2_v1_accuracy.pkl", 'rb'))
            app.logger.info('...:::Model Statistics is Loaded:::...')
          
            automl_train_test_statistics = pd.read_pickle(open("./engine/implicitPreProcessing_automl_wMetadata_wSections_experimental_results_automl_train_test_statistics_p2_v1_accuracy.pkl", 'rb'))
            app.logger.info('...:::Model Train-Test Statistics is Loaded:::...')


            app.logger.info("----------Metadata_Extractor_From_Files----------STARTED----------")

            #filename = file
            df_etc = pd.read_pickle("./engine/csai_malware_detection_val_none.pkl")
            df_main = df_etc.head(0)
            
            df_new = metadata_runner(samplename, df_main)
            app.logger.info("Runner function is finished")    
            
            save_full_name = unknwn_output_dir + samplename + "_without_feature_engineering.pkl"
            app.logger.info(save_full_name)
            
            df_new.to_pickle(save_full_name) # save
            app.logger.info(save_full_name + " file is created")   

            df_fe  = feature_engineering(df_new)
            app.logger.info("feature_engineering function is finished")
            app.logger.info(df_fe["label"].value_counts())
      
            df_fe.to_pickle(unknwn_output_dir + samplename + ".pkl") # save
            app.logger.info(samplename + ".pkl file is created")

            app.logger.info("----------Metadata_Extractor_From_Files----------FINISHED----------")

            app.logger.info("----------> " + samplename)
            app.logger.info("----------> " + modeltype)

            
            #parsed_string = parse_string_with_underscore_to_list(modeltype)
            parsed_string = modeltype.split('_')
            model_number = parsed_string[8]
            app.logger.info("----------> " + model_number)

            X_runtime = df_fe
            app.logger.info("---1")
            y_runtime = X_runtime['label']
            del X_runtime['label']
            app.logger.info("---2")
            for column in X_runtime:
                X_runtime[column] = X_runtime[column].astype("category").cat.codes
            app.logger.info("---3")
            del X_runtime['file_version_number']
            del X_runtime['product_version_number']
            del X_runtime['file_flags']
            app.logger.info("---4")
            #df = pd.read_pickle("./engine/csai_malware_detection_val_none.pkl")
            #df_main = df.head(0)

            try:
                y_test_pred = automl.predict_proba(X_runtime)
            except Exception as e:
                print("An exception occurred:", e) 
            
            app.logger.info("---5")
            app.logger.info("----------> " + y_test_pred[:,1])
            app.logger.info("---6")
            #df_fe.to_pickle(unknwn_output_dir + file_name  + ".pkl") # save


            #flash("This sample most likely not malware. No malicious signs detected in the file Metadata  ")
            #flash("This sample can be malware. We advice you to perform further test it via a Malware Detector  ")  

            return render_template(
                                'filescanjob.html', 
                                title='File Scan Result',
                                year=datetime.now().year,
                                filename=samplename,
                                modeltype=modeltype,
                                message='by COSIC Malware Analyser.'
                                )
        except:
          return 'ERROR!:Loading data'
        #return redirect_filescan()
    return 'No file uploaded'



############################################################################################################









############################################################################################################


#upload file and redirect filescanjob.html
@app.route('/uploader', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            #return redirect(url_for('download_file', name=filename))
            #return redirect('static/my_pages/filescanjob.html')
            flash("This sample is uploaded")
            return render_template(
                                   'filescanjob.html', 
                                   title='File Scan',
                                   year=datetime.now().year,
                                   filename=filename,
                                   message='Imec-COSIC.'
                                  )

            #return redirect_filescan()
        return 'No file uploaded'


############################################################################################################


#Analyser 
@app.route('/analyser', methods=['GET', 'POST'])
def run_analyser():
    isAnalyse = request.args.get('analyse_button')
    isModel = request.args.get('model')
    if request.method == 'GET':
        if isAnalyse == 'analyse':
            #pass # do something
            flash("This sample potentially Malware")
            return 'File analyzed'
        elif isModel == 'Medium':
            return 'XXXXXXX'
    if request.method == 'POST':
        return 'POST Method'


############################################################################################################


@app.route('/filescan', methods=['GET', 'POST'])
def redirect_filescan():
    isAnalyse = request.args.get('analyse_button')
    isModel = request.args.get('model')
    FileName='test'
    import pandas as pd
    data = {
        'Name': ['John', 'Anna', 'Peter', 'Linda'],
        'Age': [28, 24, 35, 32],
        'City': ['New York', 'Paris', 'Berlin', 'London']
    }
    df = pd.DataFrame(data)
    return render_template('static/my_pages/dataframe.html', tables=[df.to_html(classes='data', header="true")])
    #return render_template('static/my_pages/df_result.html',  tables=[df.to_html(classes='data')], titles=df.columns.values)
    #return render_template('dataframe.html')


############################################################################################################