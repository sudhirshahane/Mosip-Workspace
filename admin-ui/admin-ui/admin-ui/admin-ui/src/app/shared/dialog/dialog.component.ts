import {
  MatDialog,
  MatDialogRef,
  MAT_DIALOG_DATA
} from '@angular/material/dialog';
import { Component, OnInit, Inject, ViewEncapsulation } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import * as appConstants from '../../app.constants';
import { DataStorageService } from 'src/app/core/services/data-storage.service';
import {
  FormGroup,
  FormControl,
  FormBuilder,
  Validators
} from '@angular/forms';
import { RequestModel } from 'src/app/core/models/request.model';
import { FilterRequest } from 'src/app/core/models/filter-request.model';
import { FilterValuesModel } from 'src/app/core/models/filter-values.model';
import { AppConfigService } from 'src/app/app-config.service';
import Utils from 'src/app/app.utils';
import { FilterModel } from 'src/app/core/models/filter.model';
import { AuditService } from 'src/app/core/services/audit.service';
import { TranslateService } from '@ngx-translate/core';
import { OptionalFilterValuesModel } from 'src/app/core/models/optional-filter-values.model';
import { HeaderService } from 'src/app/core/services/header.service';
import { LogoutService } from './../../core/services/logout.service';

@Component({
  selector: 'app-dialog',
  templateUrl: './dialog.component.html',
  styleUrls: ['./dialog.component.scss'],
  encapsulation: ViewEncapsulation.None
})
export class DialogComponent implements OnInit {
  input;
  confirm = true;
  FilterData = [];
  missingData = [];
  noMissingDataFlag = false;
  filterGroup = new FormGroup({});
  routeParts: string;
  filters = [];
  existingFilters: any;
  filtersRequest: FilterRequest;
  filterModel: FilterValuesModel;
  requestModel: RequestModel;
  options = [];
  createUpdateSteps: any  = {};
  momentDate: any;
  primaryLangCode: string;
  requiredError = false;
  rangeError = false;
  fieldName = '';

  cancelApplied = false;

  filterOptions: any = {};

  holidayForm: FormGroup;
  sitealignment = 'ltr';

  constructor(
    public dialog: MatDialog,
    public dialogRef: MatDialogRef<DialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: any,
    private router: Router,
    private dataStorageService: DataStorageService,
    private config: AppConfigService,
    private activatedRoute: ActivatedRoute,
    private auditService: AuditService,
    private translate: TranslateService,
    private headerService: HeaderService,
    private logoutService: LogoutService
  ) {
    this.primaryLangCode = this.headerService.getUserPreferredLanguage();
    this.translate.use(this.primaryLangCode);
    if(this.primaryLangCode === "ara"){
      this.sitealignment = 'rtl';
    }
  }

  async ngOnInit() {
    this.input = this.data;
    console.log(this.input);
    if (this.input.case === 'filter') {
      this.existingFilters = Utils.convertFilter(
        this.activatedRoute.snapshot.queryParams,
        this.headerService.getUserPreferredLanguage()
      ).filters;      
      await this.getFilterMappings();
    }
    if (this.input.case === 'missingData') {
      await this.getMissingData(this.input);
    }
    if (this.input.case === 'STEPS-MESSAGE') {
      await this.getStepsForCreateUpate();
    }
  }

  get f() {
    return this.holidayForm.controls;
  }

  onNoClick(): void {
    this.auditService.audit(11, 'ADM-091', this.routeParts);
    this.cancelApplied = true;
    this.dialog.closeAll();
  }

  dismiss(): void {
    this.dialog.closeAll();
  }

  logout() {
    this.logoutService.logout();
  }

  async getFilterMappings() {
    return new Promise((resolve, reject) => {
      this.routeParts = this.router.url.split('/')[3];
      let specFileName = "";
      if(!this.routeParts.includes("view")){
        specFileName = appConstants.FilterMapping[`${this.routeParts}`].specFileName;
      }else{
        this.routeParts = this.router.url.split('/')[2];
        specFileName = appConstants.FilterMapping[`${this.routeParts}`].specFileName;
      }      
      this.dataStorageService
        .getFiltersForListView(specFileName)
        .subscribe(response => {
          // tslint:disable-next-line:no-string-literal
          this.FilterData = [...response['filterColumns']];
          this.FilterData.forEach(values => {
            if(values.filtername === "locationCode")
              this.getLocationHierarchyLevels();
          });
          this.settingUpFilter(response['filterColumns']);
          // tslint:disable-next-line:no-string-literal          
          resolve(true);
        });
    });
  }

  getLocationHierarchyLevels() {
    let self = this;
    let fieldNameData = {};
    this.dataStorageService.getLocationHierarchyLevels(this.primaryLangCode).subscribe(response => {
      response.response.locationHierarchyLevels.forEach(function (value) {
        if(value.hierarchyLevel == self.config.getConfig()['locationHierarchyLevel'])            
          self.FilterData.forEach((values, index) => {
            if(values.filtername === self.primaryLangCode)
              self.FilterData[index].filterlabel["eng"] = values.filtername;
          });     
      });
    });
  }

  getMissingData(input: any) {
    return new Promise((resolve, reject) => {
      this.dataStorageService
        .getMissingData(this.primaryLangCode, input.fieldName)
        .subscribe(response => {
          if (response.response.length > 0) {
            this.noMissingDataFlag = false;
            this.missingData = response.response;
          } else {
            this.noMissingDataFlag = true;
          }
          resolve(true);
        });
    });
  }

  navigateToItem(data: any) {
    const routeIndex = this.router.url.lastIndexOf('/');
    let currentRoute = this.router.url.slice(0, routeIndex);
    const currentRouteType = this.router.url.split('/')[3];
    const id = appConstants.ListViewIdKeyMapping[`${currentRouteType}`];
    this.auditService.audit(7, id.auditEventId, currentRouteType);
    this.dialog.closeAll();
    this.router.navigateByUrl(`${currentRoute}/single-view/`+data["id"]+'?langCode='+data.langCode);
    /*this.router.navigate([
      `${currentRoute}/single-view`,
      data["id"], 
      {"langCode": data.langCode}
    ]);*/
  }

  settingUpFilter(filterNames: any) {
    filterNames.forEach(values => {
      const filterOption = this.existingFilters.filter(
        (filter: FilterModel) =>
          filter.columnName.toLowerCase() === values.filtername.toLowerCase()
      );
      if (filterOption.length === 0) {
        this.filterGroup.addControl(values.filtername, new FormControl(''));
        this.filterOptions[values.filtername] = [];
      } else {
        let value = '';
        if (filterOption[0].type === 'startsWith') {
          value = filterOption[0].value + '*';
        } else if (filterOption[0].type === 'contains') {
          value = filterOption[0].value;
        } else {
          value = filterOption[0].value;
        }
        this.filterGroup.addControl(values.filtername, new FormControl(value));
        if (values.autocomplete === 'false' && values.dropdown === 'false') {
          this.filterOptions[values.filtername] = [];
        } else {
          this.getFilterValues(
            values.fieldName,
            filterOption[0].value,
            values.apiName,
            filterOption[0].columnName
          );
        }
      }
    });
    this.settingUpBetweenFilters(filterNames);
  }

  settingUpBetweenFilters(filterNames: any) {
    this.existingFilters.forEach((filters: FilterModel) => {
      if (filters.type === 'between') {
        const formFields = filterNames.filter(
          filterName => filterName.fieldName === filters.columnName
        );
        this.filterGroup.controls[formFields[0].filtername].setValue(
          filters.fromValue
        );
        this.filterGroup.controls[formFields[1].filtername].setValue(
          filters.toValue
        );
      }
    });
  }

  convertDate(dateString: string) {
    const date = new Date(dateString);
    let returnDate = date.getFullYear() + '-';
    returnDate +=
      Number(date.getMonth() + 1) < 10
        ? '0' + Number(date.getMonth() + 1)
        : Number(date.getMonth() + 1);
    returnDate += '-';
    returnDate +=
      Number(date.getDate()) < 10
        ? '0' + Number(date.getDate())
        : Number(date.getDate());
    return returnDate;
  }

  createBetweenFilter(filterDetails: any) {
    const existingFilter = this.existingFilters.filter(
      filters => filters.columnName === filterDetails.fieldName
    );
    if (existingFilter.length > 0) {
      const index = this.existingFilters.indexOf(existingFilter[0]);
      if (filterDetails.filtername.indexOf('From') >= 0) {
        if (filterDetails.datePicker === 'true') {
          this.momentDate = this.convertDate(
            this.filterGroup.controls[filterDetails.filtername].value
          );
          this.existingFilters[index].fromValue = this.momentDate;
        } else {
          this.existingFilters[index].fromValue = this.filterGroup.controls[
            filterDetails.filtername
          ].value;
        }
      } else if (filterDetails.filtername.indexOf('To') >= 0) {
        if (filterDetails.datePicker === 'true') {
          this.momentDate = this.convertDate(
            this.filterGroup.controls[filterDetails.filtername].value
          );
          this.existingFilters[index].toValue = this.momentDate;
        } else {
          this.existingFilters[index].toValue = this.filterGroup.controls[
            filterDetails.filtername
          ].value;
        }
      }
    } else {
      const filterModel = new FilterModel(filterDetails.fieldName, 'between');
      if (filterDetails.filtername.indexOf('From') >= 0) {
        if (filterDetails.datePicker === 'true') {
          this.momentDate = this.convertDate(
            this.filterGroup.controls[filterDetails.filtername].value
          );
          filterModel.fromValue = this.momentDate;
        } else {
          filterModel.fromValue = this.filterGroup.controls[
            filterDetails.filtername
          ].value;
        }
      } else if (filterDetails.filtername.indexOf('To') >= 0) {
        if (filterDetails.datePicker === 'true') {
          this.momentDate = this.convertDate(
            this.filterGroup.controls[filterDetails.filtername].value
          );
          filterModel.toValue = this.momentDate;
        } else {
          filterModel.toValue = this.filterGroup.controls[
            filterDetails.filtername
          ].value;
        }
      }
      this.existingFilters.push(filterModel);
    }
  }

  validateBetweenFilter(filterModel: FilterModel[], isDate: boolean[]) {
    return new Promise((resolve, reject) => {
      filterModel.forEach(filter => {
        if (
          filter.fromValue === '' ||
          filter.fromValue === undefined ||
          filter.fromValue === null ||
          (filter.toValue === '' ||
            filter.toValue === undefined ||
            filter.toValue === null)
        ) {
          this.requiredError = true;
          this.fieldName = filter.columnName;
        } else {
          this.requiredError = false;
        }
        if (isDate[filterModel.indexOf(filter)]) {
          const fromDate = new Date(filter.fromValue);
          const toDate = new Date(filter.toValue);
          if (fromDate > toDate) {
            this.rangeError = true;
            this.fieldName = filter.columnName;
          } else {
            this.rangeError = false;
          }
        } else {
          if (filter.fromValue > filter.toValue) {
            this.rangeError = true;
            this.fieldName = filter.columnName;
          } else {
            this.rangeError = false;
          }
        }
      });
      resolve(true);
    });
  }

  async getFilterValuesOnSubmit() {
    this.existingFilters = [];
    Object.keys(this.filterGroup.controls).forEach(key => {
      const filter = this.FilterData.filter(data => data.filtername === key);
      let flag = false;
      if (
        this.filterGroup.controls[key].value &&
        this.filterGroup.controls[key].value !== ''
      ) {
        let filterType = '';
        if (filter[0].filterType === 'between') {
          this.createBetweenFilter(filter[0]);
          flag = true;
        } else if (
          filter[0].dropdown === 'false' &&
          filter[0].autocomplete === 'false'
        ) {
          if (
            this.filterGroup.controls[key].value.toString().endsWith('*') &&
            this.filterGroup.controls[key].value.toString().startsWith('*')
          ) {
            filterType = 'contains';
          } else if (
            this.filterGroup.controls[key].value.toString().endsWith('*')
          ) {
            filterType = 'startsWith';
          } else if (
            this.filterGroup.controls[key].value.toString().includes('*')
          ) {
            filterType = 'contains';
          } else {
            filterType = 'contains';
          }
        } else if (
          filter[0].dropdown === 'false' &&
          filter[0].autocomplete === 'true'
        ) {
          if (
            this.filterGroup.controls[key].value.toString().endsWith('*') &&
            this.filterGroup.controls[key].value.toString().startsWith('*')
          ) {
            filterType = 'contains';
          } else if (
            this.filterGroup.controls[key].value.toString().endsWith('*')
          ) {
            filterType = 'contains';
          } else if (
            this.filterGroup.controls[key].value.toString().includes('*')
          ) {
            filterType = 'contains';
          } else {
            filterType = 'contains';
          }
        } else if (
          filter[0].dropdown === 'true' &&
          filter[0].autocomplete === 'false'
        ) {
          filterType = 'equals';
        }
        console.log("filterType>>>"+filterType);
        if (!flag) {
          const filterObject = new FilterModel(
            key === 'Zone' && this.routeParts === 'centers'
              ? key.toLowerCase()
              : key,
            filterType,
            this.filterGroup.controls[key].value.toString().indexOf('*') === -1
              ? this.filterGroup.controls[key].value
              : this.filterGroup.controls[key].value.replace(/\*/g, '')
          );
          this.existingFilters.push(filterObject);
        }
      }
    });
    const betweenFilter = this.existingFilters.filter(
      (item: FilterModel) => item.type === 'between'
    );
    if (betweenFilter.length > 0) {
      const isDate = [];
      betweenFilter.forEach(f => {
        const temp = this.FilterData.filter(
          data => data.fieldName === f.columnName
        );
        if (temp[0]['datePicker'] === 'true') {
          isDate.push(true);
        } else {
          isDate.push(false);
        }
      });
      await this.validateBetweenFilter(betweenFilter, isDate);
    } else {
      this.requiredError = false;
      this.rangeError = false;
    }
    if (
      !this.requiredError &&
      !this.rangeError &&
      this.filterGroup.valid &&
      !this.cancelApplied
    ) {
      this.auditService.audit(12, 'ADM-092', this.routeParts);
      const filters = Utils.convertFilter(
        this.activatedRoute.snapshot.queryParams,
        this.headerService.getUserPreferredLanguage()
      );
      filters.pagination.pageStart = 0;
      filters.filters = this.existingFilters;
      const url = Utils.convertFilterToUrl(filters);
      this.dialog.closeAll();
      this.router.navigateByUrl(this.router.url.split('?')[0] + '?' + url);
    }
  }

  getControlName(filter: any, value: string) {
    if (!(filter.dropdown === 'false' && filter.autocomplete === 'false')) {
      this.getFilterValues(
        filter.fieldName,
        filter.dropdown === 'true' ? undefined : value,
        filter.apiName,
        filter.filtername
      );
    }
  }

  getFilterValues(
    columnName: string,
    value: string,
    type: string,
    controlName: string
  ) {
    this.options = [];
    this.filters = [];
    const apitype = type;
    this.filterModel = new FilterValuesModel(
      columnName,
      'unique',
      value === undefined || value === null ? '' : value
    );
    this.filters = [this.filterModel];
    let optinalFilterObject = [];
    if(value){
      optinalFilterObject = [{"columnName":columnName,"type":"contains","value":value}];
    }    
    this.filtersRequest = new FilterRequest(
      this.filters,
      this.routeParts === 'blocklisted-words'
        ? 'all'
        : this.headerService.getUserPreferredLanguage(),
      optinalFilterObject
    );
    this.requestModel = new RequestModel('', null, this.filtersRequest);
    this.dataStorageService
      .getFiltersForAllMaterDataTypes(apitype, this.requestModel)
      .subscribe(response => {
        this.filterOptions[controlName] = [...response.response.filters];
      });
  }
  getStepsForCreateUpate() {
    return new Promise((resolve, reject) => {
      this.dataStorageService
        .getCreateUpdateSteps(this.input.entity)
        .subscribe(response => {
           this.createUpdateSteps.title = response['title'];
           resolve(true);
        });
    });
  }
}
