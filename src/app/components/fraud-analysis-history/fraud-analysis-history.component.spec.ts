import { ComponentFixture, TestBed } from '@angular/core/testing';

import { FraudAnalysisHistoryComponent } from './fraud-analysis-history.component';

describe('FraudAnalysisHistoryComponent', () => {
  let component: FraudAnalysisHistoryComponent;
  let fixture: ComponentFixture<FraudAnalysisHistoryComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [FraudAnalysisHistoryComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(FraudAnalysisHistoryComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
