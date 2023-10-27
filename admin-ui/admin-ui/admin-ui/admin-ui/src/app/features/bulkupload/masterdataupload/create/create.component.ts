import {Component,  ViewEncapsulation} from '@angular/core';
import { FormGroup, FormBuilder, Validators } from '@angular/forms';
import { MatDialog } from '@angular/material/dialog';
import { Location } from '@angular/common';
import { Router, NavigationEnd } from '@angular/router';
import { BulkuploadService } from 'src/app/core/services/bulkupload.service';
import { DataStorageService } from 'src/app/core/services/data-storage.service';
import { DialogComponent } from 'src/app/shared/dialog/dialog.component';
import { HeaderService } from 'src/app/core/services/header.service';
import { TranslateService } from '@ngx-translate/core';
import { AppConfigService } from 'src/app/app-config.service';
import { saveAs } from 'file-saver';
import { AuditService } from 'src/app/core/services/audit.service';

@Component({
  selector: 'app-create',
  templateUrl: './create.component.html',
  styleUrls: ["./create.component.css"],
  encapsulation: ViewEncapsulation.None
})
export class CreateComponent {
  primaryLang: string;
  uploadForm: FormGroup;
  labelanddatas:any;
  subscribed: any;
  popupMessages:any;
  fileNameError:boolean = false;
  buttonalignment = 'ltr';
  serverError:any;
  tableName: string;
  showDownloadBtn:boolean = false;
  constructor(
  private translateService: TranslateService,
  private headerService: HeaderService,
  private bulkuploadService: BulkuploadService,
  private dataStorageService: DataStorageService,
  private location: Location,
  private formBuilder: FormBuilder,
  private router: Router,
  private dialog: MatDialog,
  private appService: AppConfigService,
  private auditService: AuditService,
  ) {
    this.subscribed = router.events.subscribe(event => {
      if (event instanceof NavigationEnd) {
        this.initializeComponent();
      }
    });
  }

  initializeComponent() {
    this.auditService.audit(23, 'ADM-332', 'Master Data Upload Form');
    this.primaryLang = this.headerService.getUserPreferredLanguage();
    if(this.primaryLang === "ara"){
      this.buttonalignment = 'rtl';
    }
    this.dataStorageService
    .getI18NLanguageFiles(this.primaryLang)
    .subscribe((response) => {
      this.labelanddatas = response["bulkUpload"];
    });
    this.translateService
    .getTranslation(this.primaryLang)
    .subscribe(response => {
      this.popupMessages = response.bulkUpload.popupMessages;
      this.serverError = response.serverError;
    });
    this.initializeForm();
  }

  initializeForm() {
    this.uploadForm = this.formBuilder.group({
      category : ['masterdata'],
      files: ['', [Validators.required]],
      fileName: ['', [Validators.required]],
      operation: ['', [Validators.required]],
      tableName: ['', [Validators.required]],
    });
  }

  captureDropDownValue(event: any) {    
    if (event.source.selected) {
      this.showDownloadBtn = true;
      this.tableName = event.source.value;
    }
  }

  downloadCSV(){
    let buildURL = window.location.origin +this.appService.getConfig().templateRepoUrl+this.tableName+".csv"
    this.dataStorageService
    .getsampletemplate(buildURL).subscribe(
      data => {
        var fileName = this.tableName+".csv";
        const contentDisposition = data.headers.get('Content-Disposition');
        if (contentDisposition) {
          const fileNameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
          const matches = fileNameRegex.exec(contentDisposition);
          if (matches != null && matches[1]) {
            fileName = matches[1].replace(/['"]/g, '');
          }
        }
        saveAs(data.body, fileName);
      },
      err => {
        console.error(err);
      });
  }
  downloadExcel(){
    let buildURL = window.location.origin +this.appService.getConfig().templateRepoUrl+this.tableName+".xlsx"
    this.dataStorageService
    .getsampletemplate(buildURL).subscribe(
      data => {
        var fileName = this.tableName+".xlsx";
        const contentDisposition = data.headers.get('Content-Disposition');
        if (contentDisposition) {
          const fileNameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
          const matches = fileNameRegex.exec(contentDisposition);
          if (matches != null && matches[1]) {
            fileName = matches[1].replace(/['"]/g, '');
          }
        }
        saveAs(data.body, fileName);
      },
      err => {
        console.error(err);
      });
  }
  
  onFileSelect(event) {
    if (event.target.files.length > 0) {
      const file = event.target.files[0];
      this.uploadForm.get('files').setValue(file);
      this.uploadForm.get('fileName').setValue(file.name);
      document.getElementById("fileName").classList.remove('addredborder');
      this.fileNameError = false;
    }
  }

  onFileClick(event){
    event.target.value = '';
    this.uploadForm.get('fileName').setValue('');
  }

  submit(){
    if (this.uploadForm.valid) {
      this.auditService.audit(24, 'ADM-333', 'Master Data Upload Form');
      let data = {};
      data = {
        case: 'CONFIRMATION',       
        title: this.popupMessages['popup1'].title,
        message: this.popupMessages['popup1'].message[0] + this.uploadForm.get('operation').value + this.popupMessages['popup1'].message[1] + this.uploadForm.get('tableName').value + this.popupMessages['popup1'].message[2],
        yesBtnTxt: this.popupMessages['popup1'].yesBtnText,
        noBtnTxt: this.popupMessages['popup1'].noBtnText
      };
      const dialogRef = this.dialog.open(DialogComponent, {
        width: '650px',
        data
      });
      dialogRef.afterClosed().subscribe(response => {   
        if(response){
          this.auditService.audit(18, 'ADM-334', 'Master Data Upload Form');
          this.saveData();
        }      
      });  
    } else {
      for (const i in this.uploadForm.controls) {
        if (this.uploadForm.controls[i]) {
          if(i === "fileName"){
            if(!this.uploadForm.get('fileName').value){
              document.getElementById("fileName").classList.add('addredborder');
              this.fileNameError = true;
            }else{
              console.log("this.uploadForm.get('fileName').value>>>"+this.uploadForm.get('fileName').value);
            }
          }else{
            this.uploadForm.controls[i].markAsTouched();
          }
          
        }
      }
    }  
  }

  saveData(){
    let self = this;
    const formData = new FormData();
    formData.append('files', self.uploadForm.get('files').value);
    formData.append('category', self.uploadForm.get('category').value);
    formData.append('operation', self.uploadForm.get('operation').value);
    formData.append('tableName', self.uploadForm.get('tableName').value);    
    self.bulkuploadService.uploadData(formData).subscribe(uploadResponse => {
      self.showMessage(uploadResponse);
    });
  }

  showMessage(uploadResponse){
    let data = {};
    let self = this;
    if(uploadResponse.errors.length == 0){
      let statusDescription : any = JSON.parse(JSON.stringify(uploadResponse.response.statusDescription));
      if(uploadResponse.response.status == "FAILED"){
        for( let prop in statusDescription ){
          //console.log( statusDescription[prop] );
        }
        data = {
          case: 'MESSAGE',
          title: this.popupMessages['popup2'].title,
          message: uploadResponse.response.statusDescription,
          btnTxt: this.popupMessages['popup2'].btnTxt
        };
      }else{
        data = {
          case: 'MESSAGE',
          title: this.popupMessages['popup3'].title,
          message: this.popupMessages['popup3'].message +" "+uploadResponse.response.transcationId,
          btnTxt: this.popupMessages['popup3'].btnTxt
        };
      }
    }else{
      let message = "";
      if(uploadResponse.errors[0].errorCode === "KER-MSD-999"){
        uploadResponse.errors.forEach((element) => {
          message = message + element.message.toString() +"\n\n";
        });
        message = this.serverError[uploadResponse.errors[0].errorCode] +"\n\n"+ message;
      }else{
        message = this.serverError[uploadResponse.errors[0].errorCode];
      }
      data = {
        case: 'MESSAGE',
        title: this.popupMessages['popup2'].title,
        message: message,
        btnTxt: this.popupMessages['popup2'].btnTxt
      };
    }
    
      
    const dialogRef = self.dialog.open(DialogComponent, {
      width: '550px',
      data
    });
    dialogRef.afterClosed().subscribe(response => {   
      if(uploadResponse.errors.length>0){
        self.uploadForm.get('fileName').setValue('');
        document.getElementById("fileName").focus();
      }else{
        self.location.back();
      }     
    });
  }
  cancel() {
    this.auditService.audit(19, 'ADM-335', 'Master Data Upload Form');
    this.location.back();
  }
}
