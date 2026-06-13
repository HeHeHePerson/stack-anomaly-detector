
package com.defense.rasp.stackmodel;

import com.defense.rasp.testdata.StackDataGenerator;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * StackTemporalEngine 单元测试
 */
public class StackTemporalEngineTest {

    @Before
    public void setUp() {
        BaselineLearningEngine.resetLearning();
    }

    @Test
    public void testStackFingerprintCreation() {
        StackTraceElement[] stack = StackDataGenerator.generateNormalWebStack();
        StackTemporalEngine.StackFingerprint fingerprint = 
                new StackTemporalEngine.StackFingerprint(stack);

        assertNotNull(fingerprint);
        assertNotNull(fingerprint.methodSignature);
        assertTrue(fingerprint.methodSignatures.size() > 0);
        assertEquals(fingerprint.fingerprintHash, fingerprint.methodSignature.hashCode());
    }

    @Test
    public void testStackFingerprintEquality() {
        StackTraceElement[] stack1 = StackDataGenerator.generateNormalWebStack();
        StackTraceElement[] stack2 = StackDataGenerator.generateNormalConfigStack();

        StackTemporalEngine.StackFingerprint fp1 = 
                new StackTemporalEngine.StackFingerprint(stack1);
        StackTemporalEngine.StackFingerprint fp2 = 
                new StackTemporalEngine.StackFingerprint(stack2);

        assertNotEquals(fp1.fingerprintHash, fp2.fingerprintHash);
    }

    @Test
    public void testTransitionNode() {
        StackTemporalEngine.TransitionNode node = 
                new StackTemporalEngine.TransitionNode("com.example.Service.methodA");

        node.recordTransition("com.example.Dao.methodB");
        node.recordTransition("com.example.Dao.methodB");
        node.recordTransition("com.example.Dao.methodC");

        assertEquals(3, node.getTotalTransitions());
        assertEquals(2.0 / 3.0, node.getProbability("com.example.Dao.methodB"), 0.001);
        assertEquals(1.0 / 3.0, node.getProbability("com.example.Dao.methodC"), 0.001);
        assertEquals(0.0, node.getProbability("com.example.Dao.methodD"), 0.001);
    }

    @Test
    public void testThreadTrajectory() {
        StackTemporalEngine.ThreadTrajectory trajectory = 
                new StackTemporalEngine.ThreadTrajectory(1L, "test-thread");

        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), 
                "com.example.ClassA.method1", 
                StackTemporalEngine.CallEvent.EventType.ENTER));
        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), 
                "com.example.ClassB.method2", 
                StackTemporalEngine.CallEvent.EventType.ENTER));

        assertEquals(2, trajectory.getEventCount());
        assertNotNull(trajectory.getRecentEvents(10));
    }

    @Test
    public void testThreadTrajectoryAnomalyDetection() {
        StackTemporalEngine.ThreadTrajectory trajectory = 
                new StackTemporalEngine.ThreadTrajectory(1L, "test-thread");

        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), 
                "org.apache.catalina.core.ApplicationFilterChain.doFilter", 
                StackTemporalEngine.CallEvent.EventType.ENTER));
        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), 
                "java.io.FileInputStream.<init>", 
                StackTemporalEngine.CallEvent.EventType.ENTER));

        java.util.List<String> anomalies = trajectory.detectAnomalies();
        
        assertTrue("应该检测到Web到IO的直接调用异常", 
                anomalies.stream().anyMatch(a -> a.contains("WEB_TO_IO_DIRECT")));
    }

    @Test
    public void testReflectionDepthDetection() {
        StackTemporalEngine.ThreadTrajectory trajectory = 
                new StackTemporalEngine.ThreadTrajectory(1L, "test-thread");

        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), 
                "java.lang.reflect.Method.invoke", 
                StackTemporalEngine.CallEvent.EventType.ENTER));
        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), 
                "java.lang.reflect.Method.invoke", 
                StackTemporalEngine.CallEvent.EventType.ENTER));
        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), 
                "java.lang.reflect.Method.invoke", 
                StackTemporalEngine.CallEvent.EventType.ENTER));
        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), 
                "java.lang.reflect.Method.invoke", 
                StackTemporalEngine.CallEvent.EventType.ENTER));

        java.util.List<String> anomalies = trajectory.detectAnomalies();
        
        assertTrue("应该检测到深度反射异常", 
                anomalies.stream().anyMatch(a -> a.contains("DEEP_REFLECTION")));
    }

    @Test
    public void testCallDepthDetection() {
        StackTemporalEngine.ThreadTrajectory trajectory = 
                new StackTemporalEngine.ThreadTrajectory(1L, "test-thread");

        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), 
                "org.apache.catalina.core.ApplicationFilterChain.doFilter", 
                StackTemporalEngine.CallEvent.EventType.ENTER));
        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), 
                "java.io.FileInputStream.<init>", 
                StackTemporalEngine.CallEvent.EventType.ENTER));

        java.util.List<String> anomalies = trajectory.detectAnomalies();
        
        assertTrue("应该检测到调用深度异常", 
                anomalies.stream().anyMatch(a -> a.contains("SHALLOW_CALL_DEPTH")));
    }
}
