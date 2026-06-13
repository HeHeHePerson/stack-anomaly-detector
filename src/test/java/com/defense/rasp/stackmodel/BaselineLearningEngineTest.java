
package com.defense.rasp.stackmodel;

import com.defense.rasp.testdata.StackDataGenerator;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * BaselineLearningEngine 单元测试
 */
public class BaselineLearningEngineTest {

    @Before
    public void setUp() {
        BaselineLearningEngine.setLearningDuration(2000);
        BaselineLearningEngine.setStartupPeriod(1000);
        BaselineLearningEngine.resetLearning();
    }

    @After
    public void tearDown() {
        BaselineLearningEngine.restoreDefaultConfig();
    }

    @Test
    public void testLearnNormalStack() {
        StackTraceElement[] stack = StackDataGenerator.generateNormalWebStack();
        StackTraceElement[] stack2 = StackDataGenerator.generateNormalConfigStack();
        
        BaselineLearningEngine.learnNormalStack(stack, true);
        BaselineLearningEngine.learnNormalStack(stack2, true);
        
        assertTrue("应该学习到至少一个指纹", BaselineLearningEngine.getLearnedFingerprintCount() >= 2);
        assertTrue("应该处于学习阶段", BaselineLearningEngine.isLearningPhase());
    }

    @Test
    public void testLearnMultipleStacks() {
        BaselineLearningEngine.learnNormalStack(StackDataGenerator.generateNormalWebStack(), true);
        BaselineLearningEngine.learnNormalStack(StackDataGenerator.generateNormalConfigStack(), true);
        BaselineLearningEngine.learnNormalStack(StackDataGenerator.generateMixedStack(), true);
        BaselineLearningEngine.learnNormalStack(StackDataGenerator.generateNormalWebStack(), false);
        BaselineLearningEngine.learnNormalStack(StackDataGenerator.generateNormalConfigStack(), false);
        
        assertTrue("应该学习到至少5个指纹", BaselineLearningEngine.getLearnedFingerprintCount() >= 5);
    }

    @Test
    public void testTransitionGraphBuilding() {
        StackTraceElement[] stack1 = StackDataGenerator.generateNormalWebStack();
        StackTraceElement[] stack2 = StackDataGenerator.generateNormalConfigStack();
        
        BaselineLearningEngine.learnNormalStack(stack1, true);
        BaselineLearningEngine.learnNormalStack(stack2, true);
        
        assertTrue("转移图应该有节点", BaselineLearningEngine.getTransitionGraphSize() > 0);
    }

    @Test
    public void testDetectAnomalyWithKnownStack() {
        StackTraceElement[] stack = StackDataGenerator.generateNormalWebStack();
        
        BaselineLearningEngine.learnNormalStack(stack, true);
        
        try {
            Thread.sleep(2500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        int score = BaselineLearningEngine.detectAnomaly(stack, "test.txt");
        
        assertEquals("已知调用栈不应该有异常分数", 0, score);
    }

    @Test
    public void testDetectAnomalyWithAttackStack() {
        for (int i = 0; i < 5; i++) {
            BaselineLearningEngine.learnNormalStack(StackDataGenerator.generateNormalWebStack(), i < 2);
            BaselineLearningEngine.learnNormalStack(StackDataGenerator.generateNormalConfigStack(), i < 2);
            BaselineLearningEngine.learnNormalStack(StackDataGenerator.generateMixedStack(), i < 2);
        }
        
        try {
            Thread.sleep(2500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        StackTraceElement[] attackStack = new StackTraceElement[] {
            new StackTraceElement("org.apache.catalina.core.ApplicationFilterChain", "doFilter", "ApplicationFilterChain.java", 1),
            new StackTraceElement("com.evil.HackerClass", "executeAttack", "HackerClass.java", 100),
            new StackTraceElement("java.lang.Runtime", "exec", "Runtime.java", 50)
        };
        
        int score = BaselineLearningEngine.detectAnomaly(attackStack, "etc/passwd");
        
        assertTrue("攻击调用栈应该检测到异常", score > 0);
    }

    @Test
    public void testLearningProgress() {
        assertEquals("初始学习进度应该是0", 0, BaselineLearningEngine.getLearningProgress());
        
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        assertTrue("学习进度应该大于0", BaselineLearningEngine.getLearningProgress() > 0);
    }

    @Test
    public void testResetLearning() {
        BaselineLearningEngine.learnNormalStack(StackDataGenerator.generateNormalWebStack(), true);
        BaselineLearningEngine.learnNormalStack(StackDataGenerator.generateNormalConfigStack(), true);
        BaselineLearningEngine.learnNormalStack(StackDataGenerator.generateMixedStack(), true);
        
        assertTrue(BaselineLearningEngine.getLearnedFingerprintCount() >= 3);
        
        BaselineLearningEngine.resetLearning();
        
        assertEquals(0, BaselineLearningEngine.getLearnedFingerprintCount());
        assertEquals(0, BaselineLearningEngine.getTransitionGraphSize());
    }
}
