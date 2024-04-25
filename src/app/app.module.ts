import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http'; 
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { CommonModule } from '@angular/common';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatDividerModule } from '@angular/material/divider';
import { MatListModule } from '@angular/material/list';
import { MatSnackBarModule } from '@angular/material/snack-bar';
import { ReactiveFormsModule } from '@angular/forms';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';


import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { NavbarComponent } from './components/navbar/navbar.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { SmartContractCardComponent } from './components/smart-contract-card/smart-contract-card.component';
import { FraudTransactionsCardComponent } from './components/fraud-transactions-card/fraud-transactions-card.component';
import { SidebarComponent } from './components/sidebar/sidebar.component';
import { DocumentationComponent } from './components/documentation/documentation.component';
import { SupportComponent } from './components/support/support.component';
import { SettingsComponent } from './components/settings/settings.component';
import { TopCardsComponent } from './components/top-cards/top-cards.component';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { RemoveSymbolsPipe } from './remove-symbols.pipe';
import { RemoveSymbolsSmartContractPipe } from './remove-symbols-smart-contract.pipe';
import { RegisterComponent } from './components/register/register.component';
import { LoginComponent } from './components/login/login.component';
import { AnalysisHistoryComponent } from './components/analysis-history/analysis-history.component';
import { FraudAnalysisHistoryComponent } from './components/fraud-analysis-history/fraud-analysis-history.component';

@NgModule({
  declarations: [
    AppComponent,
    NavbarComponent,
    DashboardComponent,
    SmartContractCardComponent,
    SidebarComponent,
    SmartContractCardComponent,
    FraudTransactionsCardComponent,
    DocumentationComponent,
    SupportComponent,
    SettingsComponent,
    TopCardsComponent,
    RemoveSymbolsPipe,
    RemoveSymbolsSmartContractPipe,
    RegisterComponent,
    LoginComponent,
    AnalysisHistoryComponent,
    FraudAnalysisHistoryComponent
  ],
  imports: [
    BrowserModule,
    CommonModule,
    FormsModule,
    MatCardModule,
    MatInputModule,
    MatListModule,
    MatSnackBarModule,
    MatDividerModule,
    ReactiveFormsModule,
    MatFormFieldModule,
    MatButtonModule,
    HttpClientModule, 
    AppRoutingModule,
    BrowserAnimationsModule,
    MatProgressSpinnerModule
  ],
  providers: [
    provideAnimationsAsync('noop'),
    provideAnimationsAsync()
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
