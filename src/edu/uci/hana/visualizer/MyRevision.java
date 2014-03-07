package edu.uci.hana.visualizer;

import java.util.ArrayList;
import java.util.LinkedList;

import com.google.gson.annotations.Expose;

public class MyRevision {
	
	private String docId;
	private String revisionId;
	
	private String author; //TODO could be not single author, waiting for GOOGLE response
	@Expose
	private int authorId; // Author's id in the authorlist
	@Expose
	private long revisionLength;
	@Expose
	private String time;
	private String title;
	private String content; // for the initial getting data from Google
	private ArrayList<MySegment> segmentsList;
	@Expose
	private LinkedList<Integer> segments;
	
	MyRevision(){
		segmentsList = new ArrayList<MySegment>();
		segments = new LinkedList<Integer>();
	}
	
	public String getDocId() {
		return docId;
	}

	public void setDocId(String docId) {
		this.docId = docId;
	}

	public String getRevisionId() {
		return revisionId;
	}

	public void setRevisionId(String revisionId) {
		this.revisionId = revisionId;
	}

	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
	}
	
	public int getAuthorId() {
		return authorId;
	}

	public void setAuthorId(int authorId) {
		this.authorId = authorId;
	}

	public long getRevisionLength() {
		return revisionLength;
	}

	public void setRevisionLength(long length) {
		this.revisionLength = length;
	}

	public String getTime() {
		return time;
	}

	public void setTime(String time) {
		this.time = time;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}

	public void addSegment(MySegment insertSegment) {
		this.segmentsList.add(insertSegment);
		this.segments.add(insertSegment.getSegmentId());
	}

	public ArrayList<MySegment> getSegments() {
		return this.segmentsList;
	}

	public void updateSegmentsIndex() {
		for(MySegment s : this.segmentsList ){
			s.setStartIndex(s.getNewStartIndex());
			s.setEndIndex(s.getNewEndIndex());
		}
		
	}
}
