import { ComponentFixture, TestBed } from '@angular/core/testing';

import { FraudTransactionsCardComponent } from './fraud-transactions-card.component';

describe('FraudTransactionsCardComponent', () => {
  let component: FraudTransactionsCardComponent;
  let fixture: ComponentFixture<FraudTransactionsCardComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [FraudTransactionsCardComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(FraudTransactionsCardComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
