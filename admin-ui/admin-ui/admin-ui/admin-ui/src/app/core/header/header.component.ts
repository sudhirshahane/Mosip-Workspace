import { Component, OnInit, Input, ViewEncapsulation } from '@angular/core';

import { SideMenuService } from '../services/side-menu.service';
import { TranslateService } from '@ngx-translate/core';
import { AppConfigService } from 'src/app/app-config.service';
import { HeaderService } from '../services/header.service';
import { DataStorageService } from '../services/data-storage.service';
import { version } from 'package.json';

import { DialogComponent } from 'src/app/shared/dialog/dialog.component';
import { MatDialog } from '@angular/material';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.scss'],
  encapsulation: ViewEncapsulation.None
})
export class HeaderComponent implements OnInit {
  @Input() screenResize: number;

  profile = {
    type: 'profile',
    name: 'Joan Doe',
    zone: 'Zonal Admin',
    profileImg: './assets/images/profile.png',
    menuList: [
      {
        displayName: {
          eng: 'Logout',
          ara: 'تسجيل خروج',
          fra: 'Se déconnecter'
        },
        route: null
      }
    ]
  };

  zone: string;
  appVersion :"";
  popupMessages: any;
  serverError: any;
  constructor(
    public sideMenuService: SideMenuService,
    private translateService: TranslateService,
    private appConfigService: AppConfigService,
    private headerService: HeaderService,
    private dialog: MatDialog,
    private dataService: DataStorageService
  ) {
    // tslint:disable-next-line:no-string-literal
    translateService.use(this.headerService.getUserPreferredLanguage()).subscribe(response => {
      this.popupMessages = response;
      this.serverError = response.serverError;
    });
    this.appVersion = appConfigService.getConfig()['version'];
  }

  ngOnInit() {
    console.log(this.appVersion);
    console.log('SreenWidth', this.screenResize);
    if (this.headerService.getUsername() !== '') {
      this.dataService
      .getLoggedInUserZone(
        this.headerService.getUsername(),
        this.headerService.getUserPreferredLanguage()
      )
      .subscribe(response => {
        if (response.response) {
          console.log(response.response.zoneName);
          this.zone = response.response.zoneName;
        }else{
            this.dialog
              .open(DialogComponent, {
                width: '650px',
                data: {
                  case: 'NOZONE',
                  title: this.popupMessages.genericmessage.errorLabel,
                  message: this.serverError[response.errors[0].errorCode],
                  btnTxt: this.popupMessages.genericmessage.successButton
                },
                disableClose: true
              });
          }
      });
    }
  }
}
