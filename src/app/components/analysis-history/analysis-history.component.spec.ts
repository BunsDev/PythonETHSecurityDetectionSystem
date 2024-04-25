import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AnalysisHistoryComponent } from './analysis-history.component';

describe('AnalysisHistoryComponent', () => {
  let component: AnalysisHistoryComponent;
  let fixture: ComponentFixture<AnalysisHistoryComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [AnalysisHistoryComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(AnalysisHistoryComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
